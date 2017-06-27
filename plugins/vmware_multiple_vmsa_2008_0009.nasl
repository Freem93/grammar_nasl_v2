#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33105);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2007-5671", "CVE-2008-2100");
  script_bugtraq_id(29552, 29549);
  script_osvdb_id(46203, 46205);
  script_xref(name:"VMSA", value:"2008-0009");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2008-0009)");
  script_summary(english:"Checks vulnerable versions of multiple VMware products");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"A VMware product installed on the remote host is affected by multiple
vulnerabilities.

  - A local privilege escalation issue in 'HGFS.sys' driver
    included with the VMware Tools package, could allow an
    unprivileged guest user to execute arbitrary code on the
    guest system. It should be noted that installing the new
    releases of the affected product will not resolve the
    issue. In order to successfully apply this patch VMware
    Tools package should be updated on each Windows based
    guest followed by a reboot of the guest system.
    (CVE-2007-5671)

  - Multiple buffer overflow vulnerabilities in VMware VIX
    API, which is disabled by default, could allow arbitrary
    code execution on the host system from the guest
    operating system. (CVE-2008-2100)");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=712
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58ed8a38");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0009.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.0.4/5.5.7 or higher.
  - VMware Player 2.0.4/1.0.6 or higher.
  - VMware Server 1.0.6 or higher.
  - VMware ACE 2.0.4 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl","vmware_server_win_detect.nasl", "vmware_player_detect.nasl","vmware_ace_detect.nasl");
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

 if (( int(v[0]) < 5 ) ||
     ( int(v[0]) == 5 && int(v[1]) < 5 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 5 && int(v[2]) < 7 ) ||
     ( int(v[0]) == 6 && int(v[1]) == 0 && int(v[2]) < 4 )
   )
     {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Workstation is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }
       else
   	 security_hole(port);
     }
}

# Check for VMware Server

version = get_kb_item("VMware/Server/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 if ( ( int(v[0]) < 1 ) ||
      ( int(v[0]) == 1  && int(v[1]) == 0 && int(v[2]) < 6 )
    )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Server is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }
       else
    	security_hole(port);
    }
}

# Check for VMware Player

version = get_kb_item("VMware/Player/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 if ( ( int(v[0]) < 1 ) ||
      ( int(v[0]) == 1  && int(v[1]) == 0 && int(v[2]) < 6 ) ||
      ( int(v[0]) == 2  && int(v[1]) == 0 && int(v[2]) < 4 )
    )
   {
     if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Player is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }
       else
        security_hole(port);
    }
}

# Check for VMware ACE.
version = get_kb_item("VMware/ACE/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 if (( int(v[0]) == 2  && int(v[1]) == 0 && int(v[2]) < 4 ))
  {
    if (report_verbosity)
    {
      report = string(
         "\n",
         "Version ",version," of VMware ACE is installed on the remote host.",
         "\n"
      );
      security_hole(port:port, extra:report);
    }
    else
       security_hole(port);
  }
}
