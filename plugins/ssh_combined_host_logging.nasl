#TRUSTED 42873b22fb8adb51024100d45bd6ec6ad3e6faec417cf4f9812d155d88e20e4dcca2a6ca1bde63a39dad85d190eb0e0b399255c3ad4f23366ad410392f640fe07b932b0cba4451970b3e7e3f2b23a181c01c05e82606d28cd19c6f59f327107a3824fff772c01ceadca9155ec67f283dc575847f9f8cf32570c62d22b39069a8796797eb8cbecc0ef69bc8d8541c61dfd9a0ad1c9f8c9e268fbff7d8b9593dfad7c3d4ca7e9be3f4c36bdfdd5655ac85e19f3f10f3b6233e57b32a0b34777bca43de343238ed74cffcfb27f8dfd5e9285e4dd09d8ec53d96f6e5c9af556e015e1ce67923db872fdd0f8acb823d1367efdb34f7d4e972389e215216cb9050fbbad0eb7cefe688bf5f6bb78c732715d6f279ef67c588a6ceeb6df310869ebfb770c19d1712f3077e17ff3bae8a70a1f44f642ddb2c6860429971ddd36ed54b589cea3c940027c91f40e04d9772d1f126bb7734ac3ea0a2d523135137d77c499a9622c543378ee3c86962845a77cc52c52eab4750944d4bcf54d9a700e78a4a031beef6e6ea9063295939620778d317ffa5dba826e6c6cfad48d8460348600e85e952d15ce9f66acb39192565831b3472f8fcf3ae72e93d986f472d9d87791fbc066b99d9db84031cb0c8df7274e8c04b3694996b1685fd36099892bb6b07c0468d3cfce47e3c5bbcf19d2940b5828c10f52382d4b5ebc889b385919fbbb7200d13

include("compat.inc");

if (description)
{
  script_id(100158);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/12");

  script_name(english:"SSH Combined Host Command Logging (Plugin Debugging)");
  script_summary(english:"Writes ssh command log for host to combined log on scanner host.");

  script_set_attribute(attribute:"synopsis", value:
"If plugin debugging is enabled, this plugin writes the ssh commands
run on the host to a combined log file in a machine readable format.");
  script_set_attribute(attribute:"description", value:
"If plugin debugging is enabled, this plugin writes the ssh commands
run on the host to a combined log file in a machine readable format.
This log file resides on the scanner host itself.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_require_keys("global_settings/enable_plugin_debugging");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("global_settings/enable_plugin_debugging");

# initialize an empty table if nothing has been logged so second call doesn't fail
query_scratchpad("CREATE TABLE IF NOT EXISTS ssh_cmd_log_json ( json_text text );");
rows = query_scratchpad("SELECT json_text FROM ssh_cmd_log_json");

if(!rows || len(rows) == 0)
  exit(0, "No ssh log entries to write.");

SSH_LOG_UUID_KEY = "ssh_log_uuid";

first_entry = FALSE;

mutex_lock(SSH_LOG_UUID_KEY);
  uuid = get_global_kb_item(SSH_LOG_UUID_KEY);
  if (isnull(uuid))
  {
    first_entry = TRUE;
    uuid = generate_uuid();
    set_global_kb_item(name: SSH_LOG_UUID_KEY, value: uuid);
  }
mutex_unlock(SSH_LOG_UUID_KEY);

scanner_os = platform();
path_separator = "/";
if (scanner_os == "WINDOWS")
  path_separator = "\";

log_file = get_tmp_dir() + path_separator + 'ssh_commands-' + uuid + '.log';

file_data = '';
if(!first_entry) file_data += ',\n';

foreach row (rows)
  file_data += row["json_text"] + ',\n';

file_data = substr(file_data, 0, strlen(file_data) - 3);

fd = file_open(name: log_file, mode: 'a');
file_write(fp: fd, data: file_data);
file_close(fd);

security_note(port:0, extra:'\nCombined log file location :\n\n  ' + log_file + '\n');
