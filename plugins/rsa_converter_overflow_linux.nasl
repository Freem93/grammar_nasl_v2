#TRUSTED a508a980f11f06e4381adc250797e7201435dbf354bd4f8e0dcf9b783cdc26fff1884d7e916edac7d07b2183828c9d3b0c96bc37f1861af2bcd2468cee86836e652d387971b855dbf1b6b2b2fab631fc1580fec21408c8a6125f3390792e5cfdc17950a721e31fdb1e34714015f4a30ed2d8c0069517584600b4d167b4d61dbbbaf81041ecaea9b1113e522e0c1dd506ebb47e2dcaf5305c4d5ad30b004e7f17912ffa57f6b0f448f6ae6de92a7a7f95294de9471c44806a6cc3776439caf22503aaab90830d1b82fe99a086192be006875f5607d740814794af910ce1c8355dc01d160443f64807fedc0463d88b8918813921e61aa57effe011f4eeaa320f1484973c30aa558de87131599f7e93f78f65bfbe9f2ea60743bdfb20f05fc5bacf8a5d1f2cffc243dc4731f9cd0f68d5ff9336962c87b934c8a82eb1317b63067aac74739e0092539570d63ead700ad53a372c50f1b8ae0d634533e7698df5775d16ad07112abd124fa5915520e21e9de8e16c9c34b85fa1df735588b1eafe7cff3c43476e20433f301e6b65524858bba193e8100e0c76baffe43653fec0b853a4706efae46565cfe0ba6e8131b204769850cc4c844822c62564652f035823d69dba7d9f29082e7b359cafac6a513b8272abf6663f80abbad60919ca1e291d209800d09dcbd20350c16f66cae5c56fb7e5f679789c58f9a3aba8d670a71da97d77
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69514);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/13");

  script_cve_id("CVE-2012-0397");
  script_bugtraq_id(52315);
  script_osvdb_id(79894);
  script_xref(name:"IAVB", value:"2012-B-0027");

  script_name(english:"RSA SecurID Software Token Converter Buffer Overflow");
  script_summary(english:"Looks for the affected application in common locations.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Linux host has an application that may be affected by a
buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"RSA SecurID Software Token Converter prior to version 2.6.1 is
affected by an overflow condition. A boundary error occurs when
handling XML-formatted '.sdtid' file strings. By convincing a user to
run the converter with a crafted file, an attacker can execute
arbitrary code.");
  script_set_attribute(attribute:"solution", value:"Update to version 2.6.1 or higher.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Mar/att-16/esa-2012-013.txt");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:securid_software_token_converter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_require_keys("Host/local_checks_enabled");
  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("find_cmd.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

fixed_ver = "2.6.1";
grep_template = "sed 's/\x00/ /g' '%%%' | egrep -oa -- '-(android|iphone) -o -p -v [0-9]+\.[0-9]+(+\.[0-9]+)? \%s'";

ret = ssh_open_connection();
if (ret == 0)
  audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());

info_t = INFO_SSH;
sock_g = ret;

init_find_cmd();

if(!xautofs_option_exists && automount_running && !thorough_tests)
  audit(AUDIT_THOROUGH);

if(xautofs_option_exists)
  find_template = "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin %%% -xautofs -maxdepth 4 -type f -name 'TokenConverter*'";
else
  find_template = "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin %%%  -maxdepth 4 -type f -name 'TokenConverter*'";

audit_report = 'Fixed version is ' + fixed_ver + '.\n';
vuln_report = "";
vulnerable = FALSE;
instances_found = 0;

if (thorough_tests)
  find_cmd = str_replace(string:find_template, find:"%%%", replace:"/root /home");
else
  find_cmd = str_replace(string:find_template, find:"%%%", replace:"");

find_output = ssh_cmd(cmd:find_cmd, timeout:60, nosh:TRUE, nosudo:FALSE);

filenames = make_list();
if (!isnull(find_output))
  filenames = split(find_output, sep:'\n');

foreach filename (filenames)
{
  # Remove newline
  filename = chomp(filename);

  # Skip blank lines
  if (filename == "")
    continue;

  # Skip filenames that don't match a strict whitelist of characters.
  # We are putting untrusted input (directory names) into a command that
  # is run as root.
  if (filename =~ "[^a-zA-Z0-9/_-]")
    continue;

  grep_cmd = str_replace(find:"%%%", replace:filename, string:grep_template);
  grep_output = ssh_cmd(cmd:grep_cmd, nosh:TRUE, nosudo:FALSE);
  if (isnull(grep_output))
    continue;

  if (grep_output !~ "-o -p -v")
  {
    audit_report += filename + ' does not look like a TokenConverter executable.\n';
    continue;
  }

  # This could fail if grep on the remote host doesn't operate like we expect
  matches = eregmatch(pattern:"-v ([0-9]+\.[0-9]+(\.[0-9]+)?) ", string:grep_output);
  if (isnull(matches) || isnull(matches[1]))
    continue;

  instances_found++;
  ver = matches[1];

  if (ver_compare(ver:ver, fix:fixed_ver, strict:FALSE) != -1)
  {
    audit_report += filename + ' is version ' + ver + '.\n';
    continue;
  }

  vulnerable = TRUE;
  vuln_report += '\n  Path          : ' + filename +
                 '\n  Version       : ' + ver +
                 '\n  Fixed version : ' + fixed_ver +
                 '\n';
}

not_found_report = "RSA SecurID Software Token Converter does not appear to be installed.";

if (!thorough_tests)
{
  not_found_report +=
    " Note that Nessus only looked in common locations (/bin, /sbin, etc.) for
    the software. If you would like Nessus to check home directories in addition
    to the common locations, please enable the 'Perofrm thorough tests'
    setting and re-scan.";
}

if (instances_found == 0)
  exit(0, not_found_report);

if (!vulnerable)
  exit(0, audit_report);

security_hole(port:kb_ssh_transport(), extra:vuln_report);
