#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48763);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/03/06 17:20:50 $");

  script_name(english:"Microsoft Windows 'CWDIllegalInDllSearch' Registry Setting");
  script_summary(english:"Reports value of CWDIllegalInDllSearch ");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is configured to prevent code execution
attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is using one of the protections provided by Microsoft
KB2264107 to mitigate binary planting attacks.  The
'CWDIllegalInDllSearch' registry entry has one of the following
settings :

  - 0xFFFFFFFF (Removes the current working directory
    from the default DLL search order)

  - 1 (Blocks a DLL Load from the current working
    directory if the current working directory is set
    to a WebDAV folder)

  - 2 (Blocks a DLL Load from the current working
    directory if the current working directory is set
    to a remote folder)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/advisory/2269637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.microsoft.com/kb/2264107"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("smb_kb2269637.nasl");
  script_require_keys("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/Session Manager/CWDIllegalInDllSearch");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


port = get_kb_item_or_exit('SMB/transport');
value = get_kb_item_or_exit('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/Session Manager/CWDIllegalInDllSearch');

if (report_verbosity > 0)
{
  report =
    '\n  Name  : HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\CWDIllegalInDllSearch' +
    '\n  Value : ' + value + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);

