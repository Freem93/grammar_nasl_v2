#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32503);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/29 00:33:21 $");

  script_cve_id("CVE-2008-2098", "CVE-2008-2099");
  script_bugtraq_id(29443, 29444);
  script_osvdb_id(45890, 45891);
  script_xref(name:"VMSA", value:"2008-0008");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2008-0008)");
  script_summary(english:"Checks vulnerable versions of multiple VMware products");
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"A VMware product installed on the remote host is affected by multiple
vulnerabilities :

  - A heap overflow vulnerability in VMware Host Guest File
    System (HGFS), could allow a guest to execute arbitrary
    code subject to the privileges of the user running 'vmx'
    process. In order to successfully exploit this issue a
    folder should be shared on the host system and sharing
    should be enabled, which is disabled by default.
    (CVE-2012-2098)

  - A vulnerability in Virtual Machine Communication
    Interface (VMCI), a 'experimental' feature designed for
    users building client-server applications, could allow
    a guest to execute arbitrary code subject to the
    privileges of the user running 'vmx' process. For
    successful exploitation of this issue VMCI feature
    should be enabled on the host. (CVE-2012-2099)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0008.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws6/doc/releasenotes_ws6.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/player2/doc/releasenotes_player2.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ace2/doc/releasenotes_ace2.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.0.4 or higher.
  - VMware Player 2.0.4 or higher.
  - VMware ACE 2.0.4 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl","vmware_player_detect.nasl", "vmware_ace_detect.nasl");
  script_require_ports("VMware/Server/Version", "VMware/ACE/Version", "VMware/Player/Version", "VMware/Workstation/Version", 139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Check for VMware Workstation

version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if ( int(v[0]) == 6 && int(v[1]) == 0 && int(v[2]) < 4 )
     {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Workstation is installed on the remote host.",
          "\n"
        );
        security_warning(port:port, extra:report);
       }
       else
   	 security_warning(port);
     }
}

# Check for VMware Player

version = get_kb_item("VMware/Player/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 if ( int(v[0]) == 2  && int(v[1]) == 0 && int(v[2]) < 4 )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Player is installed on the remote host.",
          "\n"
        );
        security_warning(port:port, extra:report);
       }
       else
        security_warning(port);
    }
}

# Check for VMware ACE

version = get_kb_item("VMware/ACE/Version");
 if (version)
 {
  v = split(version, sep:".", keep:FALSE);
  if ( int(v[0]) == 2  && int(v[1]) == 0 && int(v[2]) < 4 )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware ACE is installed on the remote host.",
          "\n"
        );
        security_warning(port:port, extra:report);
       }
       else
        security_warning(port);
    }
  }

