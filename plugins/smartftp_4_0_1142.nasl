#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50575);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/10/24 19:37:29 $");

  script_bugtraq_id(44737);
  script_xref(name:"Secunia", value:"42060");

  script_name(english:"SmartFTP 'filename' Unspecified Vulnerability");
  script_summary(english:"Checks version of SmartFTP.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a FTP client installed that is affected
by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of SmartFTP earlier than
4.0.1142 installed.  Such versions are potentially affected by an
unspecified vulnerability relating to filenames.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6241afca");
  script_set_attribute(attribute:"solution", value:"Upgrade to SmartFTP 4.0.1142 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("smartftp_detect.nasl");
  script_require_keys("SMB/SmartFTP/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/SmartFTP/Version');
install_path = get_kb_item('SMB/SmartFTP/Path');
if (isnull(install_path)) install_path = 'n/a';

fixed_version = '4.0.1142.0';
if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since SmartFTP "+version+" is installed.");
