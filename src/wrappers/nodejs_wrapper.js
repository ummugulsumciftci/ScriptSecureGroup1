const fs = require("fs");
const path = require("path");
const child_process = require("child_process");

// Zero-trust evaluate (engine aynası)
function evaluate(request) {
  // process -> engine zaten DENY ediyor
  if (request.resource_type === "process") {
    return { decision: "DENY", reason: "Process execution yasak" };
  }

  const resolved = path.resolve(request.resource);

  if (
    resolved.startsWith("/tmp") ||
    resolved.startsWith(process.cwd())
  ) {
    return { decision: "ALLOW" };
  }

  return { decision: "DENY", reason: "Path PoLP ihlali" };
}

// FS wrappers
function secureReadFile(file, options) {
  const res = evaluate({
    subject: "node_script",
    resource_type: "file",
    resource: file,
    action: "read"
  });

  if (res.decision === "DENY") {
    throw new Error(`ScriptSecure: ${res.reason}`);
  }

  return fs.readFileSync(file, options);
}

function secureWriteFile(file, data, options) {
  const res = evaluate({
    subject: "node_script",
    resource_type: "file",
    resource: file,
    action: "write"
  });

  if (res.decision === "DENY") {
    throw new Error(`ScriptSecure: ${res.reason}`);
  }

  return fs.writeFileSync(file, data, options);
}

// Process -> default deny
function secureExec() {
  throw new Error("ScriptSecure: OS komutları yasak");
}

function enableNodeSandbox() {
  fs.readFileSync = secureReadFile;
  fs.writeFileSync = secureWriteFile;
  child_process.exec = secureExec;
  child_process.execSync = secureExec;

  console.log("✅ Node.js sandbox aktif (PoLP)");
}

module.exports = { enableNodeSandbox };
