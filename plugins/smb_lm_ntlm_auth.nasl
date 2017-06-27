#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63478);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/11 21:33:04 $");

  script_name(english:"Microsoft Windows LM / NTLMv1 Authentication Enabled");
  script_summary(english:"Checks registry");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is configured to use an insecure authentication
protocol."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is configured to attempt LM and/or NTLMv1 for outbound
authentication.  These protocols use weak encryption.  A remote attacker
who is able to read LM or NTLMv1 challenge and response packets could
exploit this to get a user's LM or NTLM hash, which would allow an
attacker to authenticate as that user."
  );
  # http://markgamache.blogspot.com/2013/01/ntlm-challenge-response-is-100-broken.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33c44acc");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2793313");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc960646.aspx");
  script_set_attribute(attribute:"solution", value:"Change the LmCompatibilityLevel setting to 3 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/registry_full_access", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

MIN_LEVEL = 3; # clients only use NTLMv2, servers accept LM/NTLM/NTLMv2

winver = get_kb_item('SMB/WindowsVersion');
if (ver_compare(ver:winver, fix:'5.2') < 0) # XP and earlier
  default = 0;
else if (winver == '5.2') # 2003
  default = 2;
else # Vista and later
  default = 3;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
reg_name = "SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel";
level = get_registry_value(handle:hklm, item:reg_name);
err = session_get_errorcode();
RegCloseKey(handle:hklm);
close_registry();

default_used = FALSE;

if (isnull(level))
{
  # make sure NULL was returned solely due to the data not existing in the registry
  if (err == ERROR_FILE_NOT_FOUND)
  {
    level = default;
    default_used = TRUE;
  }
  else
    audit(AUDIT_FN_FAIL, 'get_registry_value', 'error code ' + error_code_to_string(err));
}

if (int(level) >= MIN_LEVEL)
  audit(AUDIT_HOST_NOT, 'affected (setting is at level ' + level + ')');

port = kb_smb_transport();

if (report_verbosity > 0)
{
  reg_name = "HKLM\" + reg_name;
  report =
    '\n  Value name : ' + reg_name +
    '\n  Value data : ' + level;
  if (default_used)
    report += ' (default value)';
  report += '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
