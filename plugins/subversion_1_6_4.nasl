#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40620);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_osvdb_id(56856);
  script_xref(name:"Secunia", value:"36184");

  script_name(english:"Apache Subversion < 1.6.4 'libsvn_delta' Library Binary Delta svndiff Stream Parsing Multiple Overflows");
  script_summary(english:"Checks Subversion Client/Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple heap
overflow issues.");
  script_set_attribute(attribute:"description", value:
"The installed version of Subversion Client or Server is affected by
multiple heap overflow issues.

Specifically, the 'libsvn_delta' library fails to perform sufficient
boundary checks before processing certain svndiff streams. An attacker
with commit access to a vulnerable Subversion server can exploit this
vulnerability from a Subversion client to trigger a heap overflow on
the server. Typically such an attack would result in a denial of
service condition or arbitrary code execution on the remote server.

An attacker can also trigger this issue from a rogue Subversion server
on a Subversion client in response to a checkout or update request.");
  script_set_attribute(attribute:"see_also", value:"http://svn.haxx.se/dev/archive-2009-08/0107.shtml");
  script_set_attribute(attribute:"see_also", value:"http://svn.haxx.se/dev/archive-2009-08/0108.shtml" );
  script_set_attribute(attribute:"see_also", value:"http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Client/Server 1.6.4 or later.

If using Subversion Client/Server 1.5.x, make sure you are using
version CollabNet binaries 1.5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);


  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("subversion_installed.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

c_installed = get_install_count(app_name:'Subversion Client');
s_installed = get_install_count(app_name:'Subversion Server');

if ( c_installed == 0 && s_installed == 0 ) audit(AUDIT_NOT_INST, 'Subversion Client/Server');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# Check each client install.
if (c_installed > 0)
{
  c_report = '';

  c_installs = get_installs(app_name:'Subversion Client');

  foreach c_install (c_installs[1])
  {
    path =     c_install['path'];
    version =  c_install['version'];
    provider = c_install['Packaged with'];

    if ( !isnull(provider) && !isnull(version) )
    {
      if(
        ver_compare(ver:version, fix:'1.5.7', strict:FALSE) == -1 ||
        # Only CollabNet provides updated 1.5.7 binaries
        (ver_compare(ver:version, fix:'1.5.7', strict:FALSE) == 0 && "CollabNet" >!< provider) ||
        (ver_compare(ver:version, fix:'1.6.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.6.4', strict:FALSE) == -1)
      )
        c_report += '\n' +
                    '\n  Version       : ' + version +
                    '\n  Packaged with : ' + provider +
                    '\n  Path          : ' + path +
                    '\n';
    }
  }
}

# Check each Server install.

if (s_installed > 0)
{
  s_report = '';

  s_installs = get_installs(app_name:'Subversion Server');

  foreach s_install (s_installs[1])
  {
    path =     s_install['path'];
    version =  s_install['version'];
    provider = s_install['Packaged with'];

    if ( !isnull(provider) && !isnull(version) )
    {
      if (
        ver_compare(ver:version, fix:'1.5.7', strict:FALSE) == -1 ||
        # Only CollabNet provides updated 1.5.7 binaries
        (ver_compare(ver:version, fix:'1.5.7', strict:FALSE) == 0 && "CollabNet" >!< provider) ||
        (ver_compare(ver:version, fix:'1.6.0', strict:FALSE) >= 0 && ver_compare(ver:version, fix:'1.6.4', strict:FALSE) == -1)
      )
        s_report += '\n' +
                    '\n  Version       : ' + version +
                    '\n  Packaged with : ' + provider +
                    '\n  Path          : ' + path +
                    '\n';
    }
  }
}

# Report if any were found to be vulnerable.

if (c_report || s_report)
{
  if (report_verbosity > 0)
  {
    report = '\n';
    if (!empty_or_null(c_report)) report += '--- Subversion Client ---' + c_report;
    if (!empty_or_null(s_report)) report += '--- Subversion Server ---' + s_report;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Subversion Client/Server');
