#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72203);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:20:54 $");

  script_cve_id("CVE-2013-5371");
  script_bugtraq_id(65102);
  script_osvdb_id(102365);

  script_name(english:"IBM Tivoli Storage Manager Client 6.3.1.x < 6.3.2.0 / 6.4.x < 6.4.1.0 ReFS Insecure File Permissions");
  script_summary(english:"Checks version of Tivoli Storage Manager Client");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Windows host is affected
by an unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager Client installed on the remote
Windows host is potentially affected by an issue in which file
permissions are not preserved when files residing on a Resilient File
System (ReFS) are backed up or restored. 

Note that the SKIPNTSECURITYPERMISSIONS option must be set to NO (the
default value) for the system to be affected by this vulnerability,
however Nessus has not tested for this option setting.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21662608");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tivoli Storage Manager Client 6.3.2.0 / 6.4.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl");
  script_require_keys("SMB/Tivoli Storage Manager Client/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Tivoli Storage Manager Client/Version");
path = get_kb_item_or_exit("SMB/Tivoli Storage Manager Client/Path");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ '^6\\.3\\.1' && ver_compare(ver:version, fix:'6.3.2.0', strict:FALSE) < 0) fix = '6.3.2.0';
else if (version =~ '^6\\.4\\.0' && ver_compare(ver:version, fix:'6.4.1.0', strict:FALSE) < 0) fix = '6.4.1.0';
else audit(AUDIT_INST_PATH_NOT_VULN, 'Tivoli Storage Manager Client', version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
