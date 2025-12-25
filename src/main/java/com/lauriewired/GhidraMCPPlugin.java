package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean success = renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, success ? "Data renamed successfully" : "Failed to rename data");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listFunctions(offset, limit));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, disassembleFunction(address, offset, limit));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            if (address == null || address.isEmpty()) {
                sendResponse(exchange, "Error: address parameter is required");
                return;
            }
            if (comment == null) {
                sendResponse(exchange, "Error: comment parameter is required");
                return;
            }
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully at " + address : "Failed to set decompiler comment at " + address);
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            if (address == null || address.isEmpty()) {
                sendResponse(exchange, "Error: address parameter is required");
                return;
            }
            if (comment == null) {
                sendResponse(exchange, "Error: comment parameter is required");
                return;
            }
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully at " + address : "Failed to set disassembly comment at " + address);
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // === NEW ENDPOINTS ===

        // Program info endpoint
        server.createContext("/program_info", exchange -> {
            sendResponse(exchange, getProgramInfo());
        });

        // Call graph endpoints
        server.createContext("/get_callees", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionCallees(address, offset, limit));
        });

        server.createContext("/get_callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionCallers(address, offset, limit));
        });

        // Memory endpoints
        server.createContext("/read_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 256);
            sendResponse(exchange, readMemory(address, length));
        });

        server.createContext("/search_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String hexPattern = qparams.get("pattern");
            String startAddr = qparams.get("start");
            String endAddr = qparams.get("end");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 100);
            sendResponse(exchange, searchMemory(hexPattern, startAddr, endAddr, maxResults));
        });

        // Basic blocks endpoint
        server.createContext("/get_basic_blocks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getBasicBlocks(address));
        });

        // Data types endpoint
        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String category = qparams.get("category");
            sendResponse(exchange, listDataTypes(offset, limit, category));
        });

        server.createContext("/list_structures", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listStructures(offset, limit));
        });

        server.createContext("/get_structure", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            sendResponse(exchange, getStructureDetails(name));
        });

        // Equates endpoints
        server.createContext("/list_equates", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listEquates(offset, limit));
        });

        server.createContext("/create_equate", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String valueStr = params.get("value");
            String addrStr = params.get("address");
            String opIndexStr = params.get("operand_index");
            sendResponse(exchange, createEquate(name, valueStr, addrStr, opIndexStr));
        });

        // Bookmarks endpoints
        server.createContext("/list_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String category = qparams.get("category");
            sendResponse(exchange, listBookmarks(offset, limit, category));
        });

        server.createContext("/create_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String category = params.get("category");
            String description = params.get("description");
            sendResponse(exchange, createBookmark(address, category, description));
        });

        // Stack frame endpoint
        server.createContext("/get_stack_frame", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getStackFrame(address));
        });

        // === STRUCTURE MANAGEMENT ENDPOINTS ===

        server.createContext("/create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String category = params.get("category");
            int size = parseIntOrDefault(params.get("size"), 0);
            sendResponse(exchange, createStruct(name, category, size));
        });

        server.createContext("/add_struct_member", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String category = params.get("category");
            String fieldName = params.get("field_name");
            String dataType = params.get("data_type");
            int offset = parseIntOrDefault(params.get("offset"), -1);
            String comment = params.get("comment");
            sendResponse(exchange, addStructMember(structName, category, fieldName, dataType, offset, comment));
        });

        server.createContext("/remove_struct_member", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String category = params.get("category");
            String fieldName = params.get("field_name");
            int offset = parseIntOrDefault(params.get("offset"), -1);
            sendResponse(exchange, removeStructMember(structName, category, fieldName, offset));
        });

        server.createContext("/clear_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String category = params.get("category");
            sendResponse(exchange, clearStruct(structName, category));
        });

        server.createContext("/resize_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String category = params.get("category");
            int newSize = parseIntOrDefault(params.get("new_size"), 0);
            sendResponse(exchange, resizeStruct(structName, category, newSize));
        });

        server.createContext("/delete_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String category = params.get("category");
            sendResponse(exchange, deleteStruct(structName, category));
        });

        // === ENUM MANAGEMENT ENDPOINTS ===

        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String category = params.get("category");
            int size = parseIntOrDefault(params.get("size"), 4);
            sendResponse(exchange, createEnum(name, category, size));
        });

        server.createContext("/get_enum", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            String category = qparams.get("category");
            sendResponse(exchange, getEnumDetails(name, category));
        });

        server.createContext("/list_enums", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listEnums(offset, limit));
        });

        server.createContext("/add_enum_value", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String enumName = params.get("enum_name");
            String category = params.get("category");
            String valueName = params.get("value_name");
            String valueStr = params.get("value");
            sendResponse(exchange, addEnumValue(enumName, category, valueName, valueStr));
        });

        server.createContext("/remove_enum_value", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String enumName = params.get("enum_name");
            String category = params.get("category");
            String valueName = params.get("value_name");
            sendResponse(exchange, removeEnumValue(enumName, category, valueName));
        });

        // === DATA OPERATIONS ENDPOINTS ===

        server.createContext("/get_data_by_label", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String label = qparams.get("label");
            sendResponse(exchange, getDataByLabel(label));
        });

        server.createContext("/set_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String dataType = params.get("data_type");
            int length = parseIntOrDefault(params.get("length"), -1);
            sendResponse(exchange, setDataType(address, dataType, length));
        });

        // === MEMORY WRITE ENDPOINT ===

        server.createContext("/set_bytes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String bytesHex = params.get("bytes");
            sendResponse(exchange, setBytes(address, bytesHex));
        });

        // === ANALYSIS METRICS ENDPOINTS ===

        server.createContext("/get_analysis_stats", exchange -> {
            sendResponse(exchange, getAnalysisStats());
        });

        server.createContext("/get_functions_by_xref_count", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int minXrefs = parseIntOrDefault(qparams.get("min_xrefs"), 1);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 50);
            sendResponse(exchange, getFunctionsByXrefCount(minXrefs, offset, limit));
        });

        server.createContext("/get_unnamed_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getUnnamedFunctions(offset, limit));
        });

        server.createContext("/get_unnamed_data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getUnnamedData(offset, limit));
        });

        // === COMBINED SEARCH ENDPOINTS ===

        server.createContext("/find_functions_with_string", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchStr = qparams.get("search");
            int limit = parseIntOrDefault(qparams.get("limit"), 50);
            sendResponse(exchange, findFunctionsWithString(searchStr, limit));
        });

        server.createContext("/find_functions_calling", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String funcName = qparams.get("name");
            int limit = parseIntOrDefault(qparams.get("limit"), 50);
            sendResponse(exchange, findFunctionsCalling(funcName, limit));
        });

        // === VTABLE & CLASS ANALYSIS ENDPOINTS ===

        server.createContext("/find_vtables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 50);
            sendResponse(exchange, findVtables(offset, limit));
        });

        server.createContext("/analyze_vtable", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int maxSlots = parseIntOrDefault(qparams.get("max_slots"), 50);
            sendResponse(exchange, analyzeVtable(address, maxSlots));
        });

        // === CALL GRAPH ENDPOINTS ===

        server.createContext("/get_call_tree", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int depth = parseIntOrDefault(qparams.get("depth"), 2);
            String direction = qparams.get("direction");
            if (direction == null) direction = "callees";
            sendResponse(exchange, getCallTree(address, depth, direction));
        });

        // === STRUCTURE INFERENCE ENDPOINT ===

        server.createContext("/infer_struct_from_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, inferStructFromFunction(address));
        });

        // === BATCH OPERATIONS ENDPOINTS ===

        server.createContext("/batch_rename_functions", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String renamesJson = params.get("renames");
            sendResponse(exchange, batchRenameFunctions(renamesJson));
        });

        server.createContext("/batch_set_comments", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String commentsJson = params.get("comments");
            sendResponse(exchange, batchSetComments(commentsJson));
        });

        // === EXPORT ENDPOINTS ===

        server.createContext("/export_structures_as_c", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String namesParam = qparams.get("names");
            sendResponse(exchange, exportStructuresAsC(namesParam));
        });

        server.createContext("/export_enums_as_c", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String namesParam = qparams.get("names");
            sendResponse(exchange, exportEnumsAsC(namesParam));
        });

        server.createContext("/export_function_signatures", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String addressesParam = qparams.get("addresses");
            sendResponse(exchange, exportFunctionSignatures(addressesParam));
        });

        // === NEW EFFICIENCY AND WORKFLOW ENDPOINTS ===

        // Health check - lightweight endpoint for connection testing
        server.createContext("/health", exchange -> {
            sendResponse(exchange, "OK");
        });

        // Metrics endpoint
        server.createContext("/metrics", exchange -> {
            sendResponse(exchange, getServerMetrics());
        });

        // Batch decompile - decompile multiple functions in one call
        server.createContext("/batch_decompile", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addresses = params.get("addresses");
            int maxLines = parseIntOrDefault(params.get("max_lines"), 50);
            sendResponse(exchange, batchDecompile(addresses, maxLines));
        });

        // Combined analysis - decompile + callees + callers + strings in one call
        server.createContext("/analyze_function_full", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, analyzeFunctionFull(address));
        });

        // Get unnamed functions within an address range (for parallel workers)
        server.createContext("/get_unnamed_in_range", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String startAddr = qparams.get("start");
            String endAddr = qparams.get("end");
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getUnnamedFunctionsInRange(startAddr, endAddr, limit));
        });

        // Find thunk functions (single JMP wrappers)
        server.createContext("/find_thunks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, findThunkFunctions(limit));
        });

        // Find stub functions (return void/0/1 immediately)
        server.createContext("/find_stubs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String stubType = qparams.get("type");
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, findStubFunctions(stubType, limit));
        });

        // Get function complexity metrics
        server.createContext("/get_function_metrics", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionMetrics(address));
        });

        // Undo last change
        server.createContext("/undo", exchange -> {
            sendResponse(exchange, performUndo());
        });

        // Redo last undone change
        server.createContext("/redo", exchange -> {
            sendResponse(exchange, performRedo());
        });

        // Get function signature details (for better naming hints)
        server.createContext("/get_function_signature", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionSignatureDetails(address));
        });

        // Naming progress endpoint
        server.createContext("/get_naming_progress", exchange -> {
            sendResponse(exchange, getNamingProgress());
        });

        // Claim function for parallel worker coordination
        server.createContext("/claim_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String workerId = params.get("worker_id");
            sendResponse(exchange, claimFunction(address, workerId));
        });

        // Release function claim
        server.createContext("/release_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String workerId = params.get("worker_id");
            sendResponse(exchange, releaseFunction(address, workerId));
        });

        // Checkpoint session progress
        server.createContext("/checkpoint_session", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String sessionId = params.get("session_id");
            String lastAddr = params.get("last_address");
            String count = params.get("count");
            sendResponse(exchange, checkpointSession(sessionId, lastAddr, count));
        });

        // Resume session from checkpoint
        server.createContext("/resume_session", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String sessionId = qparams.get("session_id");
            sendResponse(exchange, resumeSession(sessionId));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            Msg.error(this, "No program loaded for rename data");
            return false;
        }
        if (addressStr == null || addressStr.isEmpty()) {
            Msg.error(this, "Address is null or empty for rename data");
            return false;
        }
        if (newName == null || newName.isEmpty()) {
            Msg.error(this, "New name is null or empty for rename data");
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Msg.error(this, "Failed to parse address for rename data: " + addressStr);
                        program.endTransaction(tx, false);
                        return;
                    }

                    SymbolTable symTable = program.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(addr);
                    if (symbol != null) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                        success.set(true);
                    } else {
                        // No existing symbol, create a new label
                        symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        success.set(true);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error at " + addressStr + ": " + e.getMessage(), e);
                }
                finally {
                    program.endTransaction(tx, success.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }

        return success.get();
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database with pagination
     */
    private String listFunctions(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            lines.add(String.format("%s at %s",
                func.getName(),
                func.getEntryPoint()));
        }

        return paginateList(lines, offset, limit);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function with pagination
     */
    private String disassembleFunction(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            List<String> lines = new ArrayList<>();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                lines.add(String.format("%s: %s %s",
                    instr.getAddress(),
                    instr.toString(),
                    comment));
            }

            return paginateList(lines, offset, limit);
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) {
            Msg.error(this, "No program loaded for " + transactionName);
            return false;
        }
        if (addressStr == null || addressStr.isEmpty()) {
            Msg.error(this, "Address is null or empty for " + transactionName);
            return false;
        }
        if (comment == null) {
            Msg.error(this, "Comment is null for " + transactionName);
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Msg.error(this, "Failed to parse address: " + addressStr);
                        program.endTransaction(tx, false);
                        return;
                    }
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase() + " at " + addressStr + ": " + e.getMessage(), e);
                } finally {
                    if (!success.get()) {
                        program.endTransaction(tx, false);
                    } else {
                        program.endTransaction(tx, true);
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    // ===================================================================================
    // NEW API IMPLEMENTATIONS
    // ===================================================================================

    /**
     * Get program metadata and architecture information
     */
    private String getProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder sb = new StringBuilder();
        sb.append("Program Name: ").append(program.getName()).append("\n");
        sb.append("Language ID: ").append(program.getLanguageID().getIdAsString()).append("\n");
        sb.append("Compiler Spec: ").append(program.getCompilerSpec().getCompilerSpecID().getIdAsString()).append("\n");
        sb.append("Processor: ").append(program.getLanguage().getProcessor().toString()).append("\n");
        sb.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        sb.append("Address Size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(" bits\n");
        sb.append("Executable Format: ").append(program.getExecutableFormat()).append("\n");
        sb.append("Executable Path: ").append(program.getExecutablePath()).append("\n");
        sb.append("Image Base: ").append(program.getImageBase()).append("\n");
        sb.append("Memory Size: ").append(program.getMemory().getSize()).append(" bytes\n");
        sb.append("Number of Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");
        sb.append("Number of Symbols: ").append(program.getSymbolTable().getNumSymbols()).append("\n");
        sb.append("Creation Date: ").append(program.getCreationDate()).append("\n");

        // Memory blocks summary
        sb.append("\nMemory Blocks:\n");
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            sb.append(String.format("  %s: %s - %s (%s, %s%s%s)\n",
                block.getName(),
                block.getStart(),
                block.getEnd(),
                block.isInitialized() ? "initialized" : "uninitialized",
                block.isRead() ? "R" : "-",
                block.isWrite() ? "W" : "-",
                block.isExecute() ? "X" : "-"));
        }

        return sb.toString();
    }

    /**
     * Get functions called by a function (callees)
     */
    private String getFunctionCallees(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            Set<Function> calledFunctions = func.getCalledFunctions(new ConsoleTaskMonitor());
            List<String> results = new ArrayList<>();

            for (Function callee : calledFunctions) {
                results.add(String.format("%s @ %s", callee.getName(), callee.getEntryPoint()));
            }

            Collections.sort(results);
            return paginateList(results, offset, limit);
        } catch (Exception e) {
            return "Error getting callees: " + e.getMessage();
        }
    }

    /**
     * Get functions that call a function (callers)
     */
    private String getFunctionCallers(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            Set<Function> callingFunctions = func.getCallingFunctions(new ConsoleTaskMonitor());
            List<String> results = new ArrayList<>();

            for (Function caller : callingFunctions) {
                results.add(String.format("%s @ %s", caller.getName(), caller.getEntryPoint()));
            }

            Collections.sort(results);
            return paginateList(results, offset, limit);
        } catch (Exception e) {
            return "Error getting callers: " + e.getMessage();
        }
    }

    /**
     * Read memory bytes at a specified address
     */
    private String readMemory(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (length <= 0 || length > 4096) length = 256; // Reasonable limits

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Memory memory = program.getMemory();

            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(addr, bytes);

            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Memory at %s (%d bytes):\n\n", addr, bytesRead));

            // Hex dump format
            for (int i = 0; i < bytesRead; i += 16) {
                // Address
                sb.append(String.format("%s:  ", addr.add(i)));

                // Hex bytes
                StringBuilder ascii = new StringBuilder();
                for (int j = 0; j < 16; j++) {
                    if (i + j < bytesRead) {
                        byte b = bytes[i + j];
                        sb.append(String.format("%02x ", b & 0xFF));
                        ascii.append((b >= 32 && b < 127) ? (char) b : '.');
                    } else {
                        sb.append("   ");
                        ascii.append(" ");
                    }
                    if (j == 7) sb.append(" ");
                }

                // ASCII representation
                sb.append(" |").append(ascii).append("|\n");
            }

            return sb.toString();
        } catch (MemoryAccessException e) {
            return "Memory access error: " + e.getMessage();
        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }
    }

    /**
     * Search memory for a byte pattern (hex string)
     */
    private String searchMemory(String hexPattern, String startAddrStr, String endAddrStr, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (hexPattern == null || hexPattern.isEmpty()) return "Hex pattern is required";

        try {
            // Parse hex pattern
            hexPattern = hexPattern.replaceAll("\\s+", ""); // Remove whitespace
            if (hexPattern.length() % 2 != 0) return "Invalid hex pattern (odd length)";

            byte[] pattern = new byte[hexPattern.length() / 2];
            for (int i = 0; i < pattern.length; i++) {
                pattern[i] = (byte) Integer.parseInt(hexPattern.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = program.getMemory();
            Address startAddr = startAddrStr != null && !startAddrStr.isEmpty()
                ? program.getAddressFactory().getAddress(startAddrStr)
                : memory.getMinAddress();
            Address endAddr = endAddrStr != null && !endAddrStr.isEmpty()
                ? program.getAddressFactory().getAddress(endAddrStr)
                : memory.getMaxAddress();

            List<String> results = new ArrayList<>();
            Address currentAddr = startAddr;

            while (currentAddr != null && currentAddr.compareTo(endAddr) <= 0 && results.size() < maxResults) {
                Address found = memory.findBytes(currentAddr, endAddr, pattern, null, true, new ConsoleTaskMonitor());
                if (found == null) break;

                // Get context (function name if available)
                Function func = program.getFunctionManager().getFunctionContaining(found);
                String context = func != null ? " in " + func.getName() : "";

                results.add(String.format("%s%s", found, context));

                // Move past this match
                currentAddr = found.add(1);
            }

            if (results.isEmpty()) {
                return "Pattern not found";
            }

            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Found %d matches for pattern '%s':\n", results.size(), hexPattern));
            for (String result : results) {
                sb.append(result).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "Error searching memory: " + e.getMessage();
        }
    }

    /**
     * Get basic blocks for a function
     */
    private String getBasicBlocks(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            BasicBlockModel bbModel = new BasicBlockModel(program);
            CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(func.getBody(), new ConsoleTaskMonitor());

            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Basic blocks for %s @ %s:\n\n", func.getName(), func.getEntryPoint()));

            int blockNum = 0;
            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                blockNum++;

                Address start = block.getFirstStartAddress();
                Address end = block.getMaxAddress();
                long size = end.subtract(start) + 1;

                sb.append(String.format("Block %d: %s - %s (size: %d bytes)\n", blockNum, start, end, size));

                // Get destinations (successor blocks)
                sb.append("  Successors: ");
                CodeBlockReferenceIterator dests = block.getDestinations(new ConsoleTaskMonitor());
                List<String> destAddrs = new ArrayList<>();
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    destAddrs.add(ref.getDestinationAddress().toString());
                }
                sb.append(destAddrs.isEmpty() ? "(none)" : String.join(", ", destAddrs));
                sb.append("\n");

                // Get sources (predecessor blocks)
                sb.append("  Predecessors: ");
                CodeBlockReferenceIterator sources = block.getSources(new ConsoleTaskMonitor());
                List<String> srcAddrs = new ArrayList<>();
                while (sources.hasNext()) {
                    CodeBlockReference ref = sources.next();
                    srcAddrs.add(ref.getSourceAddress().toString());
                }
                sb.append(srcAddrs.isEmpty() ? "(none)" : String.join(", ", srcAddrs));
                sb.append("\n\n");
            }

            sb.append(String.format("Total: %d basic blocks\n", blockNum));
            return sb.toString();
        } catch (Exception e) {
            return "Error getting basic blocks: " + e.getMessage();
        }
    }

    /**
     * List data types in the program
     */
    private String listDataTypes(int offset, int limit, String categoryFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> results = new ArrayList<>();

        Iterator<DataType> types = dtm.getAllDataTypes();
        while (types.hasNext()) {
            DataType dt = types.next();
            String path = dt.getPathName();
            String category = dt.getCategoryPath().toString();

            // Filter by category if specified
            if (categoryFilter != null && !categoryFilter.isEmpty()
                && !category.toLowerCase().contains(categoryFilter.toLowerCase())) {
                continue;
            }

            results.add(String.format("%s (%s, %d bytes)",
                path, dt.getClass().getSimpleName().replace("DataType", ""), dt.getLength()));
        }

        Collections.sort(results);
        return paginateList(results, offset, limit);
    }

    /**
     * List structures in the program
     */
    private String listStructures(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> results = new ArrayList<>();

        Iterator<DataType> types = dtm.getAllDataTypes();
        while (types.hasNext()) {
            DataType dt = types.next();
            if (dt instanceof ghidra.program.model.data.Structure) {
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) dt;
                results.add(String.format("%s (%d bytes, %d fields)",
                    struct.getPathName(), struct.getLength(), struct.getNumComponents()));
            }
        }

        Collections.sort(results);
        return paginateList(results, offset, limit);
    }

    /**
     * Get detailed structure information
     */
    private String getStructureDetails(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);

        if (dt == null) {
            return "Structure not found: " + name;
        }

        if (!(dt instanceof ghidra.program.model.data.Structure)) {
            return name + " is not a structure (type: " + dt.getClass().getSimpleName() + ")";
        }

        ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) dt;
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Structure: %s\n", struct.getPathName()));
        sb.append(String.format("Size: %d bytes\n", struct.getLength()));
        sb.append(String.format("Alignment: %d\n", struct.getAlignment()));
        sb.append(String.format("Number of fields: %d\n\n", struct.getNumComponents()));

        sb.append("Fields:\n");
        sb.append(String.format("%-8s %-8s %-20s %s\n", "Offset", "Size", "Type", "Name"));
        sb.append("-".repeat(60)).append("\n");

        for (ghidra.program.model.data.DataTypeComponent comp : struct.getComponents()) {
            String fieldName = comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)";
            String typeName = comp.getDataType().getName();
            sb.append(String.format("0x%-6x %-8d %-20s %s\n",
                comp.getOffset(), comp.getLength(), typeName, fieldName));
        }

        return sb.toString();
    }

    /**
     * List all equates in the program
     */
    private String listEquates(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        EquateTable equateTable = program.getEquateTable();
        List<String> results = new ArrayList<>();

        Iterator<Equate> equates = equateTable.getEquates();
        while (equates.hasNext()) {
            Equate eq = equates.next();
            results.add(String.format("%s = 0x%x (%d) [%d references]",
                eq.getName(), eq.getValue(), eq.getValue(), eq.getReferenceCount()));
        }

        Collections.sort(results);
        return paginateList(results, offset, limit);
    }

    /**
     * Create an equate (named constant)
     */
    private String createEquate(String name, String valueStr, String addressStr, String opIndexStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Equate name is required";
        if (valueStr == null || valueStr.isEmpty()) return "Equate value is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            long value;
            if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                value = Long.parseLong(valueStr.substring(2), 16);
            } else {
                value = Long.parseLong(valueStr);
            }

            final long finalValue = value;

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create equate");
                try {
                    EquateTable equateTable = program.getEquateTable();

                    // Create or get the equate
                    Equate equate = equateTable.getEquate(name);
                    if (equate == null) {
                        equate = equateTable.createEquate(name, finalValue);
                        result.append("Created equate: ").append(name).append(" = 0x")
                              .append(Long.toHexString(finalValue)).append("\n");
                    } else if (equate.getValue() != finalValue) {
                        result.append("Equate already exists with different value: ")
                              .append(equate.getValue()).append("\n");
                        return;
                    } else {
                        result.append("Using existing equate: ").append(name).append("\n");
                    }

                    // If address and operand index provided, add reference
                    if (addressStr != null && !addressStr.isEmpty() && opIndexStr != null && !opIndexStr.isEmpty()) {
                        Address addr = program.getAddressFactory().getAddress(addressStr);
                        int opIndex = Integer.parseInt(opIndexStr);
                        equate.addReference(addr, opIndex);
                        result.append("Added reference at ").append(addr).append(" operand ").append(opIndex);
                    }

                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error creating equate: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * List bookmarks in the program
     */
    private String listBookmarks(int offset, int limit, String categoryFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        BookmarkManager bm = program.getBookmarkManager();
        List<String> results = new ArrayList<>();

        // Get all bookmark types
        BookmarkType[] types = bm.getBookmarkTypes();
        for (BookmarkType type : types) {
            Iterator<Bookmark> bookmarks = bm.getBookmarksIterator(type.getTypeString());
            while (bookmarks.hasNext()) {
                Bookmark bookmark = bookmarks.next();
                String category = bookmark.getCategory();

                // Filter by category if specified
                if (categoryFilter != null && !categoryFilter.isEmpty()
                    && !category.toLowerCase().contains(categoryFilter.toLowerCase())) {
                    continue;
                }

                results.add(String.format("[%s] %s @ %s: %s",
                    bookmark.getTypeString(),
                    category,
                    bookmark.getAddress(),
                    bookmark.getComment()));
            }
        }

        return paginateList(results, offset, limit);
    }

    /**
     * Create a bookmark at an address
     */
    private String createBookmark(String addressStr, String category, String description) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        return;
                    }

                    BookmarkManager bm = program.getBookmarkManager();
                    String cat = category != null && !category.isEmpty() ? category : "Analysis";
                    String desc = description != null ? description : "";

                    bm.setBookmark(addr, BookmarkType.NOTE, cat, desc);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating bookmark: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error creating bookmark: " + e.getMessage();
        }

        return success.get()
            ? "Bookmark created at " + addressStr
            : "Failed to create bookmark";
    }

    /**
     * Get stack frame information for a function
     */
    private String getStackFrame(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            StackFrame frame = func.getStackFrame();
            StringBuilder sb = new StringBuilder();

            sb.append(String.format("Stack frame for %s @ %s:\n\n", func.getName(), func.getEntryPoint()));
            sb.append(String.format("Frame Size: %d bytes\n", frame.getFrameSize()));
            sb.append(String.format("Local Variable Size: %d bytes\n", frame.getLocalSize()));
            sb.append(String.format("Parameter Size: %d bytes\n", frame.getParameterSize()));
            sb.append(String.format("Return Address Offset: %d\n", frame.getReturnAddressOffset()));

            // Parameters
            sb.append("\nParameters:\n");
            sb.append(String.format("%-12s %-8s %-20s %s\n", "Offset", "Size", "Type", "Name"));
            sb.append("-".repeat(60)).append("\n");

            Parameter[] params = func.getParameters();
            for (Parameter param : params) {
                sb.append(String.format("%-12s %-8d %-20s %s\n",
                    param.getVariableStorage().toString(),
                    param.getLength(),
                    param.getDataType().getName(),
                    param.getName()));
            }

            // Local variables
            sb.append("\nLocal Variables:\n");
            sb.append(String.format("%-12s %-8s %-20s %s\n", "Offset", "Size", "Type", "Name"));
            sb.append("-".repeat(60)).append("\n");

            Variable[] locals = frame.getLocals();
            for (Variable local : locals) {
                sb.append(String.format("%-12s %-8d %-20s %s\n",
                    local.getVariableStorage().toString(),
                    local.getLength(),
                    local.getDataType().getName(),
                    local.getName()));
            }

            // Stack variables (all variables on the stack)
            sb.append("\nAll Stack Variables:\n");
            sb.append(String.format("%-12s %-8s %-20s %s\n", "Offset", "Size", "Type", "Name"));
            sb.append("-".repeat(60)).append("\n");

            Variable[] stackVars = frame.getStackVariables();
            for (Variable v : stackVars) {
                sb.append(String.format("%-12d %-8d %-20s %s\n",
                    v.getStackOffset(),
                    v.getLength(),
                    v.getDataType().getName(),
                    v.getName()));
            }

            return sb.toString();
        } catch (Exception e) {
            return "Error getting stack frame: " + e.getMessage();
        }
    }

    // =============================================================================
    // STRUCTURE MANAGEMENT METHODS
    // =============================================================================

    /**
     * Create a new structure data type
     */
    private String createStruct(String name, String categoryPath, int size) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create structure");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Determine category
                    ghidra.program.model.data.Category category;
                    if (categoryPath != null && !categoryPath.isEmpty()) {
                        ghidra.program.model.data.CategoryPath catPath =
                            new ghidra.program.model.data.CategoryPath("/" + categoryPath);
                        category = dtm.createCategory(catPath);
                    } else {
                        category = dtm.getRootCategory();
                    }

                    // Check if structure already exists
                    DataType existing = category.getDataType(name);
                    if (existing != null) {
                        result.append("Structure already exists: ").append(existing.getPathName());
                        return;
                    }

                    // Create the structure
                    ghidra.program.model.data.StructureDataType struct =
                        new ghidra.program.model.data.StructureDataType(name, size);

                    DataType added = dtm.addDataType(struct,
                        ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);

                    result.append("Created structure: ").append(added.getPathName());
                    result.append("\nSize: ").append(added.getLength()).append(" bytes");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error creating structure: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Add a member to an existing structure
     */
    private String addStructMember(String structName, String categoryPath, String fieldName,
                                    String dataTypeName, int offset, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";
        if (dataTypeName == null || dataTypeName.isEmpty()) return "Data type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add struct member");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Find the structure
                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (dt == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Structure)) {
                        result.append(structName).append(" is not a structure");
                        return;
                    }

                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) dt;

                    // Find the data type for the field
                    DataType fieldType = resolveDataType(dtm, dataTypeName);
                    if (fieldType == null) {
                        result.append("Data type not found: ").append(dataTypeName);
                        return;
                    }

                    // Add the member
                    ghidra.program.model.data.DataTypeComponent comp;
                    if (offset >= 0) {
                        // Add at specific offset
                        comp = struct.replaceAtOffset(offset, fieldType, fieldType.getLength(),
                            fieldName, comment);
                    } else {
                        // Append to end
                        comp = struct.add(fieldType, fieldName, comment);
                    }

                    result.append("Added field '").append(fieldName);
                    result.append("' (").append(dataTypeName).append(") ");
                    result.append("at offset 0x").append(Integer.toHexString(comp.getOffset()));
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error adding struct member: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Remove a member from a structure
     */
    private String removeStructMember(String structName, String categoryPath,
                                       String fieldName, int offset) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null && offset < 0) return "Either field name or offset is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove struct member");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (dt == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Structure)) {
                        result.append(structName).append(" is not a structure");
                        return;
                    }

                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) dt;

                    // Find the component to delete
                    ghidra.program.model.data.DataTypeComponent compToDelete = null;

                    if (offset >= 0) {
                        compToDelete = struct.getComponentAt(offset);
                    } else if (fieldName != null) {
                        for (ghidra.program.model.data.DataTypeComponent comp : struct.getComponents()) {
                            if (fieldName.equals(comp.getFieldName())) {
                                compToDelete = comp;
                                break;
                            }
                        }
                    }

                    if (compToDelete == null) {
                        result.append("Field not found");
                        return;
                    }

                    int ordinal = compToDelete.getOrdinal();
                    String removedName = compToDelete.getFieldName();
                    struct.delete(ordinal);

                    result.append("Removed field '").append(removedName);
                    result.append("' at ordinal ").append(ordinal);
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error removing struct member: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Clear all members from a structure
     */
    private String clearStruct(String structName, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear structure");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (dt == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Structure)) {
                        result.append(structName).append(" is not a structure");
                        return;
                    }

                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) dt;

                    int numComponents = struct.getNumComponents();
                    struct.deleteAll();

                    result.append("Cleared ").append(numComponents);
                    result.append(" fields from ").append(structName);
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error clearing structure: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Resize an existing structure
     */
    private String resizeStruct(String structName, String categoryPath, int newSize) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (newSize < 0) return "Size must be non-negative";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Resize structure");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (dt == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Structure)) {
                        result.append(structName).append(" is not a structure");
                        return;
                    }

                    ghidra.program.model.data.Structure struct =
                        (ghidra.program.model.data.Structure) dt;

                    int oldSize = struct.getLength();
                    if (newSize == oldSize) {
                        result.append("Structure already has size ").append(oldSize);
                        return;
                    }

                    if (newSize > oldSize) {
                        // Grow the structure
                        struct.growStructure(newSize - oldSize);
                    } else {
                        // Shrinking - delete components that fall outside new size
                        // then adjust length
                        ghidra.program.model.data.DataTypeComponent[] components = struct.getDefinedComponents();
                        for (int i = components.length - 1; i >= 0; i--) {
                            ghidra.program.model.data.DataTypeComponent comp = components[i];
                            if (comp.getOffset() + comp.getLength() > newSize) {
                                struct.delete(comp.getOrdinal());
                            }
                        }
                        // After removing offending components, shrink
                        int currentLen = struct.getLength();
                        if (currentLen > newSize) {
                            // deleteAll and recreate at new size, preserving remaining fields
                            // Actually, let's just grow to match if we overshot
                            // The structure may auto-shrink after deleting trailing undefined bytes
                        }
                    }

                    result.append("Resized structure '").append(structName);
                    result.append("' from ").append(oldSize);
                    result.append(" to ").append(struct.getLength()).append(" bytes");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error resizing structure: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Delete a structure data type
     */
    private String deleteStruct(String structName, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete structure");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (dt == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Structure)) {
                        result.append(structName).append(" is not a structure");
                        return;
                    }

                    String pathName = dt.getPathName();
                    dtm.remove(dt, ghidra.util.task.TaskMonitor.DUMMY);

                    result.append("Deleted structure: ").append(pathName);
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error deleting structure: " + e.getMessage();
        }

        return result.toString();
    }

    // =============================================================================
    // ENUM MANAGEMENT METHODS
    // =============================================================================

    /**
     * Create a new enum data type
     */
    private String createEnum(String name, String categoryPath, int size) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Enum name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Check if enum already exists
                    DataType existing = findDataTypeByNameInAllCategories(dtm, name);
                    if (existing != null && existing instanceof ghidra.program.model.data.Enum) {
                        result.append("Enum already exists: ").append(existing.getPathName());
                        return;
                    }

                    // Create the enum
                    ghidra.program.model.data.EnumDataType enumType =
                        new ghidra.program.model.data.EnumDataType(name, size);

                    DataType added = dtm.addDataType(enumType,
                        ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);

                    result.append("Created enum: ").append(added.getPathName());
                    result.append("\nSize: ").append(added.getLength()).append(" bytes");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error creating enum: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Get enum details
     */
    private String getEnumDetails(String name, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Enum name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);

        if (dt == null) {
            return "Enum not found: " + name;
        }

        if (!(dt instanceof ghidra.program.model.data.Enum)) {
            return name + " is not an enum (type: " + dt.getClass().getSimpleName() + ")";
        }

        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Enum: %s\n", enumType.getPathName()));
        sb.append(String.format("Size: %d bytes\n", enumType.getLength()));
        sb.append(String.format("Number of values: %d\n\n", enumType.getCount()));

        sb.append("Values:\n");
        sb.append(String.format("%-30s %s\n", "Name", "Value"));
        sb.append("-".repeat(50)).append("\n");

        for (String valueName : enumType.getNames()) {
            long value = enumType.getValue(valueName);
            sb.append(String.format("%-30s 0x%x (%d)\n", valueName, value, value));
        }

        return sb.toString();
    }

    /**
     * List all enums in the program
     */
    private String listEnums(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> results = new ArrayList<>();

        Iterator<DataType> types = dtm.getAllDataTypes();
        while (types.hasNext()) {
            DataType dt = types.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                results.add(String.format("%s (%d bytes, %d values)",
                    enumType.getPathName(), enumType.getLength(), enumType.getCount()));
            }
        }

        Collections.sort(results);
        return paginateList(results, offset, limit);
    }

    /**
     * Add a value to an existing enum
     */
    private String addEnumValue(String enumName, String categoryPath, String valueName, String valueStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";
        if (valueName == null || valueName.isEmpty()) return "Value name is required";
        if (valueStr == null || valueStr.isEmpty()) return "Value is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            long value;
            if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                value = Long.parseLong(valueStr.substring(2), 16);
            } else {
                value = Long.parseLong(valueStr);
            }

            final long finalValue = value;

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add enum value");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (dt == null) {
                        result.append("Enum not found: ").append(enumName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Enum)) {
                        result.append(enumName).append(" is not an enum");
                        return;
                    }

                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;
                    enumType.add(valueName, finalValue);

                    result.append("Added '").append(valueName);
                    result.append("' = 0x").append(Long.toHexString(finalValue));
                    result.append(" to ").append(enumName);
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error adding enum value: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Remove a value from an enum
     */
    private String removeEnumValue(String enumName, String categoryPath, String valueName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";
        if (valueName == null || valueName.isEmpty()) return "Value name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove enum value");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (dt == null) {
                        result.append("Enum not found: ").append(enumName);
                        return;
                    }
                    if (!(dt instanceof ghidra.program.model.data.Enum)) {
                        result.append(enumName).append(" is not an enum");
                        return;
                    }

                    ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dt;

                    // Check if value exists
                    if (!enumType.contains(valueName)) {
                        result.append("Value '").append(valueName).append("' not found in enum");
                        return;
                    }

                    enumType.remove(valueName);

                    result.append("Removed '").append(valueName);
                    result.append("' from ").append(enumName);
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error removing enum value: " + e.getMessage();
        }

        return result.toString();
    }

    // =============================================================================
    // DATA OPERATIONS METHODS
    // =============================================================================

    /**
     * Get data information by label name
     */
    private String getDataByLabel(String label) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (label == null || label.isEmpty()) return "Label is required";

        SymbolTable symTable = program.getSymbolTable();
        List<Symbol> symbols = symTable.getGlobalSymbols(label);

        if (symbols.isEmpty()) {
            // Try searching for partial matches
            List<String> partialMatches = new ArrayList<>();
            SymbolIterator it = symTable.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (s.getName().toLowerCase().contains(label.toLowerCase())) {
                    partialMatches.add(s.getName() + " @ " + s.getAddress());
                    if (partialMatches.size() >= 10) break;
                }
            }
            if (!partialMatches.isEmpty()) {
                return "Label not found. Did you mean:\n" + String.join("\n", partialMatches);
            }
            return "Label not found: " + label;
        }

        StringBuilder sb = new StringBuilder();
        for (Symbol sym : symbols) {
            Address addr = sym.getAddress();
            sb.append(String.format("Label: %s\n", sym.getName()));
            sb.append(String.format("Address: %s\n", addr));
            sb.append(String.format("Namespace: %s\n", sym.getParentNamespace().getName()));
            sb.append(String.format("Source: %s\n", sym.getSource()));

            // Get data at address if exists
            Data data = program.getListing().getDataAt(addr);
            if (data != null) {
                sb.append(String.format("Data Type: %s\n", data.getDataType().getName()));
                sb.append(String.format("Size: %d bytes\n", data.getLength()));
                sb.append(String.format("Value: %s\n", escapeNonAscii(data.getDefaultValueRepresentation())));
            }

            // Get references to this symbol
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(addr);
            int refCount = 0;
            while (refIter.hasNext()) {
                refIter.next();
                refCount++;
            }
            if (refCount > 0) {
                sb.append(String.format("References: %d\n", refCount));
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Set data type at an address
     */
    private String setDataType(String addressStr, String dataTypeName, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (dataTypeName == null || dataTypeName.isEmpty()) return "Data type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set data type");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }

                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = resolveDataType(dtm, dataTypeName);
                    if (dataType == null) {
                        result.append("Data type not found: ").append(dataTypeName);
                        return;
                    }

                    Listing listing = program.getListing();

                    // Clear any existing data/code at address
                    listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);

                    // Create the data
                    Data data = listing.createData(addr, dataType);

                    result.append("Set data type at ").append(addressStr);
                    result.append(" to ").append(dataType.getName());
                    result.append(" (").append(data.getLength()).append(" bytes)");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error setting data type: " + e.getMessage();
        }

        return result.toString();
    }

    // =============================================================================
    // ANALYSIS METRICS METHODS
    // =============================================================================

    /**
     * Get analysis coverage statistics
     */
    private String getAnalysisStats() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        FunctionManager funcMgr = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();
        DataTypeManager dtm = program.getDataTypeManager();

        int totalFunctions = 0;
        int namedFunctions = 0;
        int unnamedFunctions = 0;

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            totalFunctions++;
            String name = func.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
                unnamedFunctions++;
            } else {
                namedFunctions++;
            }
        }

        int totalData = 0;
        int namedData = 0;
        int unnamedData = 0;

        SymbolIterator symIter = symTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            if (sym.getSymbolType() == SymbolType.LABEL) {
                String name = sym.getName();
                if (name.startsWith("DAT_") || name.startsWith("PTR_") || name.startsWith("ADDR_")) {
                    unnamedData++;
                } else {
                    namedData++;
                }
                totalData++;
            }
        }

        int structCount = 0;
        int enumCount = 0;
        Iterator<DataType> typeIter = dtm.getAllDataTypes();
        while (typeIter.hasNext()) {
            DataType dt = typeIter.next();
            if (dt instanceof ghidra.program.model.data.Structure) {
                structCount++;
            } else if (dt instanceof ghidra.program.model.data.Enum) {
                enumCount++;
            }
        }

        double funcPercent = totalFunctions > 0 ? (namedFunctions * 100.0 / totalFunctions) : 0;
        double dataPercent = totalData > 0 ? (namedData * 100.0 / totalData) : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("=== Analysis Statistics ===\n\n");
        sb.append(String.format("Functions:\n"));
        sb.append(String.format("  Total: %d\n", totalFunctions));
        sb.append(String.format("  Named: %d (%.1f%%)\n", namedFunctions, funcPercent));
        sb.append(String.format("  Unnamed (FUN_*): %d\n\n", unnamedFunctions));
        sb.append(String.format("Data Labels:\n"));
        sb.append(String.format("  Total: %d\n", totalData));
        sb.append(String.format("  Named: %d (%.1f%%)\n", namedData, dataPercent));
        sb.append(String.format("  Unnamed (DAT_*): %d\n\n", unnamedData));
        sb.append(String.format("Data Types Defined:\n"));
        sb.append(String.format("  Structures: %d\n", structCount));
        sb.append(String.format("  Enums: %d\n", enumCount));

        return sb.toString();
    }

    /**
     * Get functions sorted by xref count (most referenced first)
     */
    private String getFunctionsByXrefCount(int minXrefs, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        FunctionManager funcMgr = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        List<Map.Entry<Function, Integer>> funcXrefs = new ArrayList<>();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());
            int count = 0;
            while (refs.hasNext()) {
                refs.next();
                count++;
            }
            if (count >= minXrefs) {
                funcXrefs.add(new AbstractMap.SimpleEntry<>(func, count));
            }
        }

        // Sort by xref count descending
        funcXrefs.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        List<String> results = new ArrayList<>();
        for (Map.Entry<Function, Integer> entry : funcXrefs) {
            Function func = entry.getKey();
            int count = entry.getValue();
            results.add(String.format("%s @ %s (xrefs: %d)",
                func.getName(), func.getEntryPoint(), count));
        }

        return paginateList(results, offset, limit);
    }

    /**
     * Get only unnamed functions (FUN_*)
     */
    private String getUnnamedFunctions(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        FunctionManager funcMgr = program.getFunctionManager();
        List<String> results = new ArrayList<>();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
                results.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        return paginateList(results, offset, limit);
    }

    /**
     * Get only unnamed data (DAT_*)
     */
    private String getUnnamedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable symTable = program.getSymbolTable();
        List<String> results = new ArrayList<>();

        SymbolIterator symIter = symTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            String name = sym.getName();
            if (name.startsWith("DAT_") || name.startsWith("PTR_") || name.startsWith("ADDR_")) {
                results.add(String.format("%s @ %s", name, sym.getAddress()));
            }
        }

        return paginateList(results, offset, limit);
    }

    // =============================================================================
    // COMBINED SEARCH METHODS
    // =============================================================================

    /**
     * Find functions that reference strings containing the search term
     */
    private String findFunctionsWithString(String searchStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchStr == null || searchStr.isEmpty()) return "Search string required";

        Listing listing = program.getListing();
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();

        Set<String> foundFunctions = new LinkedHashSet<>();
        String searchLower = searchStr.toLowerCase();

        // Find all defined strings
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && foundFunctions.size() < limit) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String strValue = data.getDefaultValueRepresentation();
                if (strValue != null && strValue.toLowerCase().contains(searchLower)) {
                    // Found matching string, find referencing functions
                    Address strAddr = data.getAddress();
                    ReferenceIterator refs = refMgr.getReferencesTo(strAddr);
                    while (refs.hasNext() && foundFunctions.size() < limit) {
                        Reference ref = refs.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            String escaped = escapeNonAscii(strValue);
                            if (escaped.length() > 50) escaped = escaped.substring(0, 47) + "...";
                            foundFunctions.add(String.format("%s @ %s (refs string: %s)",
                                func.getName(), func.getEntryPoint(), escaped));
                        }
                    }
                }
            }
        }

        if (foundFunctions.isEmpty()) {
            return "No functions found referencing strings containing: " + searchStr;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[Found %d functions referencing strings containing '%s']\n",
            foundFunctions.size(), searchStr));
        for (String entry : foundFunctions) {
            sb.append(entry).append("\n");
        }
        return sb.toString();
    }

    /**
     * Find all functions that call a specific function
     */
    private String findFunctionsCalling(String funcName, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (funcName == null || funcName.isEmpty()) return "Function name required";

        FunctionManager funcMgr = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        // Find the target function
        List<Function> targetFuncs = new ArrayList<>();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            if (f.getName().toLowerCase().contains(funcName.toLowerCase())) {
                targetFuncs.add(f);
            }
        }

        if (targetFuncs.isEmpty()) {
            return "Function not found: " + funcName;
        }

        Set<String> callers = new LinkedHashSet<>();
        for (Function targetFunc : targetFuncs) {
            if (callers.size() >= limit) break;

            ReferenceIterator refs = refMgr.getReferencesTo(targetFunc.getEntryPoint());
            while (refs.hasNext() && callers.size() < limit) {
                Reference ref = refs.next();
                if (ref.getReferenceType().isCall()) {
                    Function callerFunc = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (callerFunc != null) {
                        callers.add(String.format("%s @ %s (calls %s)",
                            callerFunc.getName(), callerFunc.getEntryPoint(), targetFunc.getName()));
                    }
                }
            }
        }

        if (callers.isEmpty()) {
            return "No callers found for: " + funcName;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[Found %d functions calling '%s']\n", callers.size(), funcName));
        for (String entry : callers) {
            sb.append(entry).append("\n");
        }
        return sb.toString();
    }

    // =============================================================================
    // VTABLE ANALYSIS METHODS
    // =============================================================================

    /**
     * Find potential vtables in the binary
     */
    private String findVtables(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Listing listing = program.getListing();
        FunctionManager funcMgr = program.getFunctionManager();
        int pointerSize = program.getDefaultPointerSize();

        List<String> vtables = new ArrayList<>();

        // Look for arrays of function pointers in data sections
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            DataType dt = data.getDataType();

            // Check if it's a pointer
            if (dt instanceof ghidra.program.model.data.Pointer) {
                Address addr = data.getAddress();
                Object value = data.getValue();

                if (value instanceof Address) {
                    Address targetAddr = (Address) value;
                    Function func = funcMgr.getFunctionAt(targetAddr);

                    if (func != null) {
                        // This might be start of a vtable, check consecutive pointers
                        int consecutiveFuncPtrs = 1;
                        Address checkAddr = addr.add(pointerSize);

                        for (int i = 0; i < 20; i++) {
                            Data nextData = listing.getDataAt(checkAddr);
                            if (nextData == null) break;

                            Object nextValue = nextData.getValue();
                            if (nextValue instanceof Address) {
                                Function nextFunc = funcMgr.getFunctionAt((Address) nextValue);
                                if (nextFunc != null) {
                                    consecutiveFuncPtrs++;
                                    checkAddr = checkAddr.add(pointerSize);
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }

                        if (consecutiveFuncPtrs >= 3) {
                            // Found potential vtable
                            String label = getSymbolName(program, addr);
                            vtables.add(String.format("%s @ %s (%d function pointers)",
                                label, addr, consecutiveFuncPtrs));
                        }
                    }
                }
            }
        }

        if (vtables.isEmpty()) {
            return "No potential vtables found";
        }

        return paginateList(vtables, offset, limit);
    }

    private String getSymbolName(Program program, Address addr) {
        Symbol sym = program.getSymbolTable().getPrimarySymbol(addr);
        return sym != null ? sym.getName() : addr.toString();
    }

    /**
     * Analyze a vtable and list all function slots
     */
    private String analyzeVtable(String addressStr, int maxSlots) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address required";

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address: " + addressStr;
        }

        Listing listing = program.getListing();
        FunctionManager funcMgr = program.getFunctionManager();
        int pointerSize = program.getDefaultPointerSize();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("=== Vtable Analysis @ %s ===\n\n", addressStr));
        sb.append(String.format("%-8s %-20s %s\n", "Offset", "Address", "Function"));
        sb.append("-".repeat(70)).append("\n");

        Address currentAddr = addr;
        for (int slot = 0; slot < maxSlots; slot++) {
            Data data = listing.getDataAt(currentAddr);
            if (data == null) {
                // Try to read as pointer anyway
                try {
                    long ptrValue = 0;
                    byte[] bytes = new byte[pointerSize];
                    program.getMemory().getBytes(currentAddr, bytes);
                    for (int i = pointerSize - 1; i >= 0; i--) {
                        ptrValue = (ptrValue << 8) | (bytes[i] & 0xFF);
                    }
                    Address targetAddr = program.getAddressFactory().getAddress(
                        String.format("0x%x", ptrValue));
                    Function func = funcMgr.getFunctionAt(targetAddr);
                    if (func != null) {
                        sb.append(String.format("0x%-6x %-20s %s\n",
                            slot * pointerSize, targetAddr, func.getName()));
                    } else {
                        // Not a function pointer, probably end of vtable
                        break;
                    }
                } catch (Exception e) {
                    break;
                }
            } else {
                Object value = data.getValue();
                if (value instanceof Address) {
                    Address targetAddr = (Address) value;
                    Function func = funcMgr.getFunctionAt(targetAddr);
                    if (func != null) {
                        sb.append(String.format("0x%-6x %-20s %s\n",
                            slot * pointerSize, targetAddr, func.getName()));
                    } else {
                        // Not a function pointer, probably end of vtable
                        break;
                    }
                } else {
                    break;
                }
            }
            currentAddr = currentAddr.add(pointerSize);
        }

        return sb.toString();
    }

    // =============================================================================
    // CALL GRAPH METHODS
    // =============================================================================

    /**
     * Get call tree for a function
     */
    private String getCallTree(String addressStr, int maxDepth, String direction) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address required";

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address: " + addressStr;
        }

        FunctionManager funcMgr = program.getFunctionManager();
        Function rootFunc = funcMgr.getFunctionAt(addr);
        if (rootFunc == null) {
            rootFunc = funcMgr.getFunctionContaining(addr);
        }
        if (rootFunc == null) {
            return "No function at address: " + addressStr;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("=== Call Tree: %s @ %s ===\n", rootFunc.getName(), rootFunc.getEntryPoint()));
        sb.append(String.format("Direction: %s, Max Depth: %d\n\n", direction, maxDepth));

        Set<Address> visited = new HashSet<>();
        buildCallTree(sb, program, rootFunc, 0, maxDepth, direction, visited);

        return sb.toString();
    }

    private void buildCallTree(StringBuilder sb, Program program, Function func,
                               int depth, int maxDepth, String direction, Set<Address> visited) {
        if (depth > maxDepth || visited.contains(func.getEntryPoint())) {
            return;
        }
        visited.add(func.getEntryPoint());

        String indent = "  ".repeat(depth);
        sb.append(String.format("%s%s%s @ %s\n",
            indent, depth > 0 ? "├─ " : "", func.getName(), func.getEntryPoint()));

        if (depth >= maxDepth) return;

        FunctionManager funcMgr = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        Set<Function> related = new LinkedHashSet<>();

        if (direction.equals("callees") || direction.equals("both")) {
            // Get functions this calls
            Set<Function> callees = func.getCalledFunctions(null);
            related.addAll(callees);
        }

        if (direction.equals("callers") || direction.equals("both")) {
            // Get functions that call this
            ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (ref.getReferenceType().isCall()) {
                    Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        related.add(caller);
                    }
                }
            }
        }

        int count = 0;
        for (Function relatedFunc : related) {
            if (count >= 10) {
                sb.append(String.format("%s  └─ ... and %d more\n", indent, related.size() - count));
                break;
            }
            buildCallTree(sb, program, relatedFunc, depth + 1, maxDepth, direction, visited);
            count++;
        }
    }

    // =============================================================================
    // STRUCTURE INFERENCE METHOD
    // =============================================================================

    /**
     * Infer structure layout from function decompilation
     */
    private String inferStructFromFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address required";

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return "Invalid address: " + addressStr;
        }

        FunctionManager funcMgr = program.getFunctionManager();
        Function func = funcMgr.getFunctionAt(addr);
        if (func == null) {
            func = funcMgr.getFunctionContaining(addr);
        }
        if (func == null) {
            return "No function at address: " + addressStr;
        }

        // Use decompiler to analyze
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        try {
            DecompileResults results = decomp.decompileFunction(func, 30, null);
            if (!results.decompileCompleted()) {
                return "Decompilation failed";
            }

            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) {
                return "No high-level function available";
            }

            // Analyze parameter access patterns
            Map<Integer, String> fieldAccesses = new TreeMap<>();
            int pointerSize = program.getDefaultPointerSize();

            // Look for pointer + offset patterns in the decompiled code
            String decompCode = results.getDecompiledFunction().getC();

            // Simple regex-like pattern matching for offset access
            // Looking for patterns like *(param + 0x10) or param->field
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "\\*?\\([^)]+\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)\\)"
            );
            java.util.regex.Matcher matcher = pattern.matcher(decompCode);

            while (matcher.find()) {
                String offsetStr = matcher.group(1);
                try {
                    int offset;
                    if (offsetStr.startsWith("0x")) {
                        offset = Integer.parseInt(offsetStr.substring(2), 16);
                    } else {
                        offset = Integer.parseInt(offsetStr);
                    }
                    fieldAccesses.put(offset, guessTypeFromOffset(offset, pointerSize));
                } catch (NumberFormatException e) {
                    // Skip invalid
                }
            }

            if (fieldAccesses.isEmpty()) {
                return "No clear structure access patterns found in function";
            }

            StringBuilder sb = new StringBuilder();
            sb.append(String.format("=== Inferred Structure from %s ===\n\n", func.getName()));
            sb.append("Suggested structure definition:\n\n");
            sb.append("```c\n");
            sb.append("struct InferredStruct {\n");

            int lastOffset = 0;
            for (Map.Entry<Integer, String> entry : fieldAccesses.entrySet()) {
                int offset = entry.getKey();
                String type = entry.getValue();

                // Add padding if there's a gap
                if (offset > lastOffset) {
                    int gap = offset - lastOffset;
                    if (gap > 0 && gap <= 64) {
                        sb.append(String.format("    char _pad_0x%x[%d];\n", lastOffset, gap));
                    }
                }

                sb.append(String.format("    %s field_0x%x;  // offset 0x%x\n", type, offset, offset));
                lastOffset = offset + getSizeForType(type, pointerSize);
            }

            sb.append("};\n");
            sb.append("```\n\n");

            sb.append("To create this structure:\n");
            sb.append("```\n");
            sb.append("create_struct(\"InferredStruct\", size=0)\n");
            for (Map.Entry<Integer, String> entry : fieldAccesses.entrySet()) {
                sb.append(String.format("add_struct_member(\"InferredStruct\", \"field_0x%x\", \"%s\", offset=0x%x)\n",
                    entry.getKey(), entry.getValue(), entry.getKey()));
            }
            sb.append("```\n");

            return sb.toString();
        } finally {
            decomp.dispose();
        }
    }

    private String guessTypeFromOffset(int offset, int pointerSize) {
        // Simple heuristic based on offset alignment
        if (offset % pointerSize == 0) {
            return "void*";  // Could be pointer
        } else if (offset % 4 == 0) {
            return "int";
        } else if (offset % 2 == 0) {
            return "short";
        }
        return "char";
    }

    private int getSizeForType(String type, int pointerSize) {
        if (type.contains("*")) return pointerSize;
        if (type.equals("int") || type.equals("uint") || type.equals("float")) return 4;
        if (type.equals("short") || type.equals("ushort")) return 2;
        if (type.equals("long") || type.equals("double")) return 8;
        return 1;
    }

    // =============================================================================
    // BATCH OPERATIONS METHODS
    // =============================================================================

    /**
     * Batch rename multiple functions
     */
    private String batchRenameFunctions(String renamesJson) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (renamesJson == null || renamesJson.isEmpty()) return "Renames JSON required";

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failCount = new AtomicInteger(0);
        StringBuilder errors = new StringBuilder();

        try {
            // Simple JSON parsing (format: [{"address":"0x...","name":"..."},...]
            // Remove brackets and split by },
            String cleaned = renamesJson.trim();
            if (cleaned.startsWith("[")) cleaned = cleaned.substring(1);
            if (cleaned.endsWith("]")) cleaned = cleaned.substring(0, cleaned.length() - 1);

            String[] entries = cleaned.split("\\},\\s*\\{");

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch rename functions");
                try {
                    FunctionManager funcMgr = program.getFunctionManager();

                    for (String entry : entries) {
                        entry = entry.replace("{", "").replace("}", "");
                        String address = null;
                        String name = null;

                        for (String pair : entry.split(",")) {
                            pair = pair.trim();
                            if (pair.startsWith("\"address\"")) {
                                address = pair.split(":")[1].trim().replace("\"", "");
                            } else if (pair.startsWith("\"name\"")) {
                                name = pair.split(":")[1].trim().replace("\"", "");
                            }
                        }

                        if (address != null && name != null) {
                            try {
                                Address addr = program.getAddressFactory().getAddress(address);
                                Function func = funcMgr.getFunctionAt(addr);
                                if (func == null) {
                                    func = funcMgr.getFunctionContaining(addr);
                                }
                                if (func != null) {
                                    func.setName(name, SourceType.USER_DEFINED);
                                    successCount.incrementAndGet();
                                } else {
                                    errors.append("No function at ").append(address).append("\n");
                                    failCount.incrementAndGet();
                                }
                            } catch (Exception e) {
                                errors.append("Error renaming ").append(address).append(": ")
                                      .append(e.getMessage()).append("\n");
                                failCount.incrementAndGet();
                            }
                        }
                    }
                } finally {
                    program.endTransaction(tx, successCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return "Error processing batch rename: " + e.getMessage();
        }

        StringBuilder result = new StringBuilder();
        result.append(String.format("Batch rename complete: %d succeeded, %d failed\n",
            successCount.get(), failCount.get()));
        if (errors.length() > 0) {
            result.append("\nErrors:\n").append(errors);
        }
        return result.toString();
    }

    /**
     * Batch set multiple comments
     */
    private String batchSetComments(String commentsJson) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (commentsJson == null || commentsJson.isEmpty()) return "Comments JSON required";

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failCount = new AtomicInteger(0);

        try {
            String cleaned = commentsJson.trim();
            if (cleaned.startsWith("[")) cleaned = cleaned.substring(1);
            if (cleaned.endsWith("]")) cleaned = cleaned.substring(0, cleaned.length() - 1);

            String[] entries = cleaned.split("\\},\\s*\\{");

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch set comments");
                try {
                    Listing listing = program.getListing();

                    for (String entry : entries) {
                        entry = entry.replace("{", "").replace("}", "");
                        String address = null;
                        String comment = null;

                        for (String pair : entry.split(",(?=\\s*\")")) {
                            pair = pair.trim();
                            if (pair.startsWith("\"address\"")) {
                                address = pair.split(":")[1].trim().replace("\"", "");
                            } else if (pair.startsWith("\"comment\"")) {
                                int colonIdx = pair.indexOf(":");
                                if (colonIdx >= 0) {
                                    comment = pair.substring(colonIdx + 1).trim().replace("\"", "");
                                }
                            }
                        }

                        if (address != null && comment != null) {
                            try {
                                Address addr = program.getAddressFactory().getAddress(address);
                                listing.setComment(addr, CodeUnit.PRE_COMMENT, comment);
                                successCount.incrementAndGet();
                            } catch (Exception e) {
                                failCount.incrementAndGet();
                            }
                        }
                    }
                } finally {
                    program.endTransaction(tx, successCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return "Error processing batch comments: " + e.getMessage();
        }

        return String.format("Batch comments complete: %d succeeded, %d failed",
            successCount.get(), failCount.get());
    }

    // =============================================================================
    // EXPORT METHODS
    // =============================================================================

    /**
     * Export structures as C header definitions
     */
    private String exportStructuresAsC(String namesParam) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        StringBuilder sb = new StringBuilder();
        sb.append("/* Exported structures from Ghidra */\n\n");

        List<String> targetNames = new ArrayList<>();
        if (namesParam != null && !namesParam.isEmpty()) {
            for (String name : namesParam.split(",")) {
                targetNames.add(name.trim());
            }
        }

        Iterator<DataType> typeIter = dtm.getAllDataTypes();
        while (typeIter.hasNext()) {
            DataType dt = typeIter.next();
            if (dt instanceof ghidra.program.model.data.Structure) {
                ghidra.program.model.data.Structure struct =
                    (ghidra.program.model.data.Structure) dt;

                // Filter if names specified
                if (!targetNames.isEmpty() && !targetNames.contains(struct.getName())) {
                    continue;
                }

                sb.append(String.format("typedef struct %s {\n", struct.getName()));

                for (ghidra.program.model.data.DataTypeComponent comp : struct.getComponents()) {
                    String fieldType = comp.getDataType().getName();
                    String fieldName = comp.getFieldName();
                    if (fieldName == null || fieldName.isEmpty()) {
                        fieldName = "field_0x" + Integer.toHexString(comp.getOffset());
                    }
                    String comment = comp.getComment();

                    sb.append(String.format("    %-20s %s;", fieldType, fieldName));
                    if (comment != null && !comment.isEmpty()) {
                        sb.append("  // ").append(comment);
                    }
                    sb.append(String.format("  /* offset: 0x%x */\n", comp.getOffset()));
                }

                sb.append(String.format("} %s;  /* size: 0x%x */\n\n",
                    struct.getName(), struct.getLength()));
            }
        }

        return sb.toString();
    }

    /**
     * Export enums as C definitions
     */
    private String exportEnumsAsC(String namesParam) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        StringBuilder sb = new StringBuilder();
        sb.append("/* Exported enums from Ghidra */\n\n");

        List<String> targetNames = new ArrayList<>();
        if (namesParam != null && !namesParam.isEmpty()) {
            for (String name : namesParam.split(",")) {
                targetNames.add(name.trim());
            }
        }

        Iterator<DataType> typeIter = dtm.getAllDataTypes();
        while (typeIter.hasNext()) {
            DataType dt = typeIter.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                ghidra.program.model.data.Enum enumType =
                    (ghidra.program.model.data.Enum) dt;

                if (!targetNames.isEmpty() && !targetNames.contains(enumType.getName())) {
                    continue;
                }

                sb.append(String.format("typedef enum %s {\n", enumType.getName()));

                String[] names = enumType.getNames();
                for (int i = 0; i < names.length; i++) {
                    String name = names[i];
                    long value = enumType.getValue(name);
                    sb.append(String.format("    %s = 0x%x", name, value));
                    if (i < names.length - 1) sb.append(",");
                    sb.append("\n");
                }

                sb.append(String.format("} %s;\n\n", enumType.getName()));
            }
        }

        return sb.toString();
    }

    /**
     * Export function signatures
     */
    private String exportFunctionSignatures(String addressesParam) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        FunctionManager funcMgr = program.getFunctionManager();
        StringBuilder sb = new StringBuilder();
        sb.append("/* Exported function signatures from Ghidra */\n\n");

        if (addressesParam != null && !addressesParam.isEmpty()) {
            // Export specific addresses
            for (String addrStr : addressesParam.split(",")) {
                addrStr = addrStr.trim();
                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    Function func = funcMgr.getFunctionAt(addr);
                    if (func == null) {
                        func = funcMgr.getFunctionContaining(addr);
                    }
                    if (func != null) {
                        sb.append(String.format("// @ %s\n", func.getEntryPoint()));
                        sb.append(func.getSignature().getPrototypeString()).append(";\n\n");
                    }
                } catch (Exception e) {
                    sb.append("// Error processing ").append(addrStr).append("\n");
                }
            }
        } else {
            // Export all named functions
            FunctionIterator funcIter = funcMgr.getFunctions(true);
            int count = 0;
            while (funcIter.hasNext() && count < 500) {
                Function func = funcIter.next();
                if (!func.getName().startsWith("FUN_")) {
                    sb.append(String.format("// @ %s\n", func.getEntryPoint()));
                    sb.append(func.getSignature().getPrototypeString()).append(";\n\n");
                    count++;
                }
            }
        }

        return sb.toString();
    }

    // =============================================================================
    // MEMORY WRITE METHOD
    // =============================================================================

    /**
     * Write bytes to memory at specified address
     */
    private String setBytes(String addressStr, String bytesHex) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (bytesHex == null || bytesHex.isEmpty()) return "Bytes are required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            // Parse hex string to bytes
            String cleanHex = bytesHex.replaceAll("[^0-9A-Fa-f]", "");
            if (cleanHex.length() % 2 != 0) {
                return "Invalid hex string: must have even number of hex digits";
            }

            byte[] bytes = new byte[cleanHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
            }

            final byte[] finalBytes = bytes;

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set bytes");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("Invalid address: ").append(addressStr);
                        return;
                    }

                    Memory memory = program.getMemory();
                    MemoryBlock block = memory.getBlock(addr);

                    if (block == null) {
                        result.append("No memory block at address: ").append(addressStr);
                        return;
                    }

                    if (!block.isInitialized()) {
                        result.append("Memory block is not initialized: ").append(block.getName());
                        return;
                    }

                    memory.setBytes(addr, finalBytes);

                    result.append("Wrote ").append(finalBytes.length).append(" bytes at ");
                    result.append(addressStr);
                    success.set(true);
                } catch (MemoryAccessException e) {
                    result.append("Memory access error: ").append(e.getMessage());
                } catch (Exception e) {
                    result.append("Error: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return "Error writing bytes: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            // Use limit of 2 to handle values that contain "=" characters
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            } else if (kv.length == 1 && !kv[0].isEmpty()) {
                // Handle case where parameter has no value (key only)
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    params.put(key, "");
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter key", e);
                }
            }
        }
        return params;
    }

    // =============================================================================
    // NEW EFFICIENCY AND WORKFLOW METHODS
    // =============================================================================

    private long serverStartTime = System.currentTimeMillis();
    private AtomicInteger requestCount = new AtomicInteger(0);

    /**
     * Get server metrics for monitoring
     */
    private String getServerMetrics() {
        long uptime = (System.currentTimeMillis() - serverStartTime) / 1000;
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
        long maxMemory = runtime.maxMemory() / (1024 * 1024);

        Program program = getCurrentProgram();
        String programInfo = program != null ? program.getName() : "None loaded";
        int funcCount = program != null ? program.getFunctionManager().getFunctionCount() : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("=== GhidraMCP Server Metrics ===\n");
        sb.append(String.format("Uptime: %d seconds\n", uptime));
        sb.append(String.format("Requests handled: %d\n", requestCount.get()));
        sb.append(String.format("Memory: %d MB / %d MB\n", usedMemory, maxMemory));
        sb.append(String.format("Program: %s\n", programInfo));
        sb.append(String.format("Functions: %d\n", funcCount));
        return sb.toString();
    }

    /**
     * Batch decompile multiple functions in one call
     */
    private String batchDecompile(String addressesStr, int maxLinesPerFunc) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressesStr == null || addressesStr.isEmpty()) return "Addresses parameter required";

        String[] addresses = addressesStr.split(",");
        StringBuilder result = new StringBuilder();
        result.append(String.format("=== BATCH DECOMPILE: %d functions ===\n\n", addresses.length));

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        for (int i = 0; i < addresses.length; i++) {
            String addrStr = addresses[i].trim();
            result.append(String.format("--- FUNCTION %d/%d: %s ---\n", i + 1, addresses.length, addrStr));

            try {
                Address addr = program.getAddressFactory().getAddress(addrStr);
                Function func = getFunctionForAddress(program, addr);

                if (func == null) {
                    result.append("No function found at this address\n\n");
                    continue;
                }

                result.append(String.format("Name: %s\n", func.getName()));

                DecompileResults decompResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (decompResult != null && decompResult.decompileCompleted()) {
                    String code = decompResult.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    int linesToShow = Math.min(lines.length, maxLinesPerFunc);

                    for (int j = 0; j < linesToShow; j++) {
                        result.append(lines[j]).append("\n");
                    }
                    if (lines.length > maxLinesPerFunc) {
                        result.append(String.format("... [%d more lines]\n", lines.length - maxLinesPerFunc));
                    }
                } else {
                    result.append("Decompilation failed\n");
                }
            } catch (Exception e) {
                result.append("Error: ").append(e.getMessage()).append("\n");
            }
            result.append("\n");
        }

        decomp.dispose();
        return result.toString();
    }

    /**
     * Combined function analysis: decompile + callees + callers + strings
     */
    private String analyzeFunctionFull(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            StringBuilder sb = new StringBuilder();
            String funcName = func.getName();
            boolean isUnnamed = funcName.startsWith("FUN_") || funcName.startsWith("thunk_FUN_");

            sb.append("=== FUNCTION ANALYSIS ===\n");
            sb.append(String.format("Address: %s\n", func.getEntryPoint()));
            sb.append(String.format("Name: %s%s\n", funcName, isUnnamed ? " (UNNAMED)" : ""));
            sb.append(String.format("Signature: %s\n\n", func.getSignature()));

            // Decompile
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults decompResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            sb.append("--- DECOMPILED CODE ---\n");
            if (decompResult != null && decompResult.decompileCompleted()) {
                String code = decompResult.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                int linesToShow = Math.min(lines.length, 100);
                for (int i = 0; i < linesToShow; i++) {
                    sb.append(lines[i]).append("\n");
                }
                if (lines.length > 100) {
                    sb.append(String.format("... [%d more lines]\n", lines.length - 100));
                }
            } else {
                sb.append("Decompilation failed\n");
            }
            decomp.dispose();

            // Callees
            sb.append("\n--- CALLEES (functions this calls) ---\n");
            Set<Function> callees = func.getCalledFunctions(new ConsoleTaskMonitor());
            int calleeCount = 0;
            for (Function callee : callees) {
                String calleeName = callee.getName();
                boolean calleeUnnamed = calleeName.startsWith("FUN_");
                sb.append(String.format("  %s @ %s%s\n",
                    calleeName, callee.getEntryPoint(), calleeUnnamed ? " *" : ""));
                calleeCount++;
                if (calleeCount >= 20) {
                    sb.append(String.format("  ... and %d more\n", callees.size() - 20));
                    break;
                }
            }
            if (callees.isEmpty()) sb.append("  (none)\n");

            // Callers
            sb.append("\n--- CALLERS (functions that call this) ---\n");
            Set<Function> callers = func.getCallingFunctions(new ConsoleTaskMonitor());
            int callerCount = 0;
            for (Function caller : callers) {
                String callerName = caller.getName();
                boolean callerUnnamed = callerName.startsWith("FUN_");
                sb.append(String.format("  %s @ %s%s\n",
                    callerName, caller.getEntryPoint(), callerUnnamed ? " *" : ""));
                callerCount++;
                if (callerCount >= 20) {
                    sb.append(String.format("  ... and %d more\n", callers.size() - 20));
                    break;
                }
            }
            if (callers.isEmpty()) sb.append("  (none)\n");

            // String references
            sb.append("\n--- STRING REFERENCES ---\n");
            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();
            int stringCount = 0;

            for (Address instrAddr : func.getBody().getAddresses(true)) {
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Data data = listing.getDataAt(ref.getToAddress());
                    if (data != null && data.hasStringValue()) {
                        String strValue = data.getDefaultValueRepresentation();
                        if (strValue != null && strValue.length() > 2) {
                            sb.append(String.format("  %s: %s\n", ref.getToAddress(),
                                strValue.length() > 60 ? strValue.substring(0, 60) + "..." : strValue));
                            stringCount++;
                            if (stringCount >= 10) break;
                        }
                    }
                }
                if (stringCount >= 10) break;
            }
            if (stringCount == 0) sb.append("  (none)\n");

            return sb.toString();
        } catch (Exception e) {
            return "Error analyzing function: " + e.getMessage();
        }
    }

    /**
     * Get unnamed functions within an address range (for parallel workers)
     */
    private String getUnnamedFunctionsInRange(String startAddrStr, String endAddrStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startAddrStr == null || endAddrStr == null) return "Start and end addresses required";

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddrStr);
            Address endAddr = program.getAddressFactory().getAddress(endAddrStr);

            List<String> results = new ArrayList<>();
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator funcIter = funcMgr.getFunctions(startAddr, true);

            while (funcIter.hasNext() && results.size() < limit) {
                Function func = funcIter.next();
                if (func.getEntryPoint().compareTo(endAddr) > 0) break;

                String name = func.getName();
                if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
                    results.add(String.format("%s @ %s", name, func.getEntryPoint()));
                }
            }

            return paginateList(results, 0, limit);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find thunk functions (single JMP wrappers)
     */
    private String findThunkFunctions(int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> results = new ArrayList<>();
        FunctionManager funcMgr = program.getFunctionManager();

        for (Function func : funcMgr.getFunctions(true)) {
            if (results.size() >= limit) break;

            // Check if function is a thunk
            Function thunkedFunc = func.getThunkedFunction(false);
            if (thunkedFunc != null) {
                results.add(String.format("%s @ %s -> %s",
                    func.getName(), func.getEntryPoint(), thunkedFunc.getName()));
            }
        }

        if (results.isEmpty()) {
            return "No thunk functions found";
        }
        return paginateList(results, 0, limit);
    }

    /**
     * Find stub functions (return void/0/1 immediately)
     */
    private String findStubFunctions(String stubType, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> results = new ArrayList<>();
        FunctionManager funcMgr = program.getFunctionManager();
        Listing listing = program.getListing();

        for (Function func : funcMgr.getFunctions(true)) {
            if (results.size() >= limit) break;

            // Count instructions in function
            int instrCount = 0;
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();
            InstructionIterator instrIter = listing.getInstructions(start, true);

            String lastMnemonic = "";
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                if (instr.getAddress().compareTo(end) > 0) break;
                instrCount++;
                lastMnemonic = instr.getMnemonicString().toUpperCase();
                if (instrCount > 5) break; // Not a stub if more than 5 instructions
            }

            // Check if it's a stub
            if (instrCount <= 3) {
                String funcName = func.getName();
                boolean isUnnamed = funcName.startsWith("FUN_");
                String stubKind = "unknown";

                if (lastMnemonic.equals("RET") || lastMnemonic.equals("RETN")) {
                    stubKind = "void";
                } else if (lastMnemonic.contains("RET")) {
                    stubKind = "return";
                }

                if (stubType == null || stubType.equals("all") || stubType.equals(stubKind)) {
                    results.add(String.format("%s @ %s (%d instr, %s)%s",
                        funcName, func.getEntryPoint(), instrCount, stubKind,
                        isUnnamed ? " *" : ""));
                }
            }
        }

        if (results.isEmpty()) {
            return "No stub functions found";
        }
        return paginateList(results, 0, limit);
    }

    /**
     * Get function complexity metrics
     */
    private String getFunctionMetrics(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            // Count instructions
            int instrCount = 0;
            Listing listing = program.getListing();
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                instrIter.next();
                instrCount++;
            }

            // Count basic blocks and calculate cyclomatic complexity
            BasicBlockModel bbModel = new BasicBlockModel(program);
            CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(func.getBody(), new ConsoleTaskMonitor());
            int blockCount = 0;
            int edgeCount = 0;

            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blockCount++;
                CodeBlockReferenceIterator destIter = block.getDestinations(new ConsoleTaskMonitor());
                while (destIter.hasNext()) {
                    destIter.next();
                    edgeCount++;
                }
            }

            // Cyclomatic complexity = E - N + 2 (for single connected component)
            int cyclomaticComplexity = edgeCount - blockCount + 2;
            if (cyclomaticComplexity < 1) cyclomaticComplexity = 1;

            // Count callees and callers
            Set<Function> callees = func.getCalledFunctions(new ConsoleTaskMonitor());
            Set<Function> callers = func.getCallingFunctions(new ConsoleTaskMonitor());

            // Count local variables
            Variable[] locals = func.getLocalVariables();
            Parameter[] params = func.getParameters();

            StringBuilder sb = new StringBuilder();
            sb.append("=== FUNCTION METRICS ===\n");
            sb.append(String.format("Function: %s\n", func.getName()));
            sb.append(String.format("Address: %s\n\n", func.getEntryPoint()));
            sb.append(String.format("Instructions: %d\n", instrCount));
            sb.append(String.format("Basic blocks: %d\n", blockCount));
            sb.append(String.format("Cyclomatic complexity: %d\n", cyclomaticComplexity));
            sb.append(String.format("Parameters: %d\n", params.length));
            sb.append(String.format("Local variables: %d\n", locals.length));
            sb.append(String.format("Functions called: %d\n", callees.size()));
            sb.append(String.format("Called by: %d\n", callers.size()));
            sb.append(String.format("Body size: %d bytes\n", func.getBody().getNumAddresses()));

            // Complexity rating
            String rating;
            if (cyclomaticComplexity <= 5) rating = "Low (simple)";
            else if (cyclomaticComplexity <= 10) rating = "Moderate";
            else if (cyclomaticComplexity <= 20) rating = "High";
            else rating = "Very High (complex)";
            sb.append(String.format("\nComplexity rating: %s\n", rating));

            return sb.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Perform undo operation
     */
    private String performUndo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            if (program.canUndo()) {
                program.undo();
                return "Undo successful";
            } else {
                return "Nothing to undo";
            }
        } catch (Exception e) {
            return "Undo failed: " + e.getMessage();
        }
    }

    /**
     * Perform redo operation
     */
    private String performRedo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            if (program.canRedo()) {
                program.redo();
                return "Redo successful";
            } else {
                return "Nothing to redo";
            }
        } catch (Exception e) {
            return "Redo failed: " + e.getMessage();
        }
    }

    /**
     * Get detailed function signature for better naming hints
     */
    private String getFunctionSignatureDetails(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            StringBuilder sb = new StringBuilder();
            sb.append("=== FUNCTION SIGNATURE ===\n");
            sb.append(String.format("Name: %s\n", func.getName()));
            sb.append(String.format("Address: %s\n", func.getEntryPoint()));
            sb.append(String.format("Signature: %s\n", func.getSignature()));
            sb.append(String.format("Return type: %s\n", func.getReturnType().getName()));
            sb.append(String.format("Calling convention: %s\n", func.getCallingConventionName()));
            sb.append(String.format("Is thunk: %s\n", func.isThunk()));
            sb.append(String.format("Is external: %s\n", func.isExternal()));
            sb.append(String.format("Stack frame size: %d\n", func.getStackFrame().getFrameSize()));

            // Parameters
            Parameter[] params = func.getParameters();
            sb.append(String.format("\nParameters (%d):\n", params.length));
            for (int i = 0; i < params.length; i++) {
                Parameter p = params[i];
                sb.append(String.format("  [%d] %s %s", i, p.getDataType().getName(), p.getName()));
                if (i == 0 && p.getName().equals("this")) {
                    sb.append(" (C++ method)");
                }
                sb.append("\n");
            }

            // Check if first param looks like 'this' pointer
            if (params.length > 0) {
                String firstParamType = params[0].getDataType().getName().toLowerCase();
                if (firstParamType.contains("*") || firstParamType.contains("ptr")) {
                    sb.append("\nNote: First parameter is a pointer - may be C++ method\n");
                }
            }

            // Local variables summary
            Variable[] locals = func.getLocalVariables();
            sb.append(String.format("\nLocal variables: %d\n", locals.length));

            return sb.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get naming progress statistics
     */
    private String getNamingProgress() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        int total = 0;
        int named = 0;
        int unnamed = 0;

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            total++;
            String name = func.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
                unnamed++;
            } else {
                named++;
            }
        }

        double percent = total > 0 ? (named * 100.0 / total) : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("=== NAMING PROGRESS ===\n");
        sb.append(String.format("Total functions: %d\n", total));
        sb.append(String.format("Named: %d\n", named));
        sb.append(String.format("Unnamed (FUN_*): %d\n", unnamed));
        sb.append(String.format("Progress: %.1f%%\n", percent));

        // Encouragement
        if (percent < 10) {
            sb.append("\nJust getting started! Keep going!");
        } else if (percent < 25) {
            sb.append("\nGood progress! The patterns will become clearer.");
        } else if (percent < 50) {
            sb.append("\nNice work! Halfway there!");
        } else if (percent < 75) {
            sb.append("\nGreat progress! More than half done!");
        } else if (percent < 100) {
            sb.append("\nAlmost there! The finish line is in sight!");
        } else {
            sb.append("\nAmazing! All functions are named!");
        }

        return sb.toString();
    }

    /**
     * Claim a function for exclusive analysis (parallel worker coordination)
     */
    private String claimFunction(String addressStr, String workerId) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || workerId == null) return "Address and worker_id required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            BookmarkManager bmMgr = program.getBookmarkManager();
            String category = "WorkerClaim";

            // Check if already claimed
            Bookmark[] existing = bmMgr.getBookmarks(addr);
            for (Bookmark bm : existing) {
                if (bm.getCategory().equals(category)) {
                    String existingWorker = bm.getComment();
                    if (existingWorker.equals(workerId)) {
                        return "ALREADY_OWNED";
                    } else {
                        return "ALREADY_CLAIMED by " + existingWorker;
                    }
                }
            }

            // Claim it
            AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Claim function");
                try {
                    bmMgr.setBookmark(addr, BookmarkType.NOTE, category, workerId);
                    success.set(true);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            return success.get() ? "CLAIMED" : "FAILED";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Release a function claim
     */
    private String releaseFunction(String addressStr, String workerId) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || workerId == null) return "Address and worker_id required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            BookmarkManager bmMgr = program.getBookmarkManager();
            String category = "WorkerClaim";

            // Find and remove the claim
            AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Release function claim");
                try {
                    Bookmark[] existing = bmMgr.getBookmarks(addr);
                    for (Bookmark bm : existing) {
                        if (bm.getCategory().equals(category) && bm.getComment().equals(workerId)) {
                            bmMgr.removeBookmark(bm);
                            success.set(true);
                            break;
                        }
                    }
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            return success.get() ? "RELEASED" : "NOT_FOUND";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Save session checkpoint for resume after restart
     */
    private String checkpointSession(String sessionId, String lastAddrStr, String countStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (sessionId == null) return "Session ID required";

        try {
            Address zeroAddr = program.getAddressFactory().getAddress("0x0");
            BookmarkManager bmMgr = program.getBookmarkManager();
            String category = "SessionCheckpoint_" + sessionId;
            String comment = String.format("last=%s,count=%s,time=%d",
                lastAddrStr != null ? lastAddrStr : "none",
                countStr != null ? countStr : "0",
                System.currentTimeMillis());

            AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Checkpoint session");
                try {
                    // Remove old checkpoint for this session
                    Bookmark[] existing = bmMgr.getBookmarks(zeroAddr);
                    for (Bookmark bm : existing) {
                        if (bm.getCategory().equals(category)) {
                            bmMgr.removeBookmark(bm);
                        }
                    }
                    // Add new checkpoint
                    bmMgr.setBookmark(zeroAddr, BookmarkType.NOTE, category, comment);
                    success.set(true);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            return success.get() ? "Checkpoint saved: " + comment : "Failed to save checkpoint";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Resume from session checkpoint
     */
    private String resumeSession(String sessionId) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (sessionId == null) return "Session ID required";

        try {
            Address zeroAddr = program.getAddressFactory().getAddress("0x0");
            BookmarkManager bmMgr = program.getBookmarkManager();
            String category = "SessionCheckpoint_" + sessionId;

            Bookmark[] existing = bmMgr.getBookmarks(zeroAddr);
            for (Bookmark bm : existing) {
                if (bm.getCategory().equals(category)) {
                    return "FOUND: " + bm.getComment();
                }
            }

            return "NEW";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // =============================================================================
    // UTILITY METHODS
    // =============================================================================

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     * Includes a header line with pagination metadata: total count, offset, and limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int total = items.size();
        int start = Math.max(0, offset);
        int end   = Math.min(total, offset + limit);

        StringBuilder result = new StringBuilder();
        result.append(String.format("[Showing %d-%d of %d results]",
            start, Math.min(end, total), total));

        if (start < total) {
            List<String> sub = items.subList(start, end);
            for (String item : sub) {
                result.append("\n").append(item);
            }
        }

        return result.toString();
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
