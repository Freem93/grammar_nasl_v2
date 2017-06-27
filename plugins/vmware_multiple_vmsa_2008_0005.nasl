#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31729);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/02/17 15:06:27 $");

  script_cve_id(
    "CVE-2006-2937",
    "CVE-2006-2940",
    "CVE-2006-4339",
    "CVE-2006-4343",
    "CVE-2007-5269",
    "CVE-2007-5618",
    "CVE-2008-0923",
    "CVE-2008-1340",
    "CVE-2008-1361",
    "CVE-2008-1362",
    "CVE-2008-1363",
    "CVE-2008-1364",
    "CVE-2008-1392"
  );
  script_bugtraq_id(28276,28289);
  script_osvdb_id(
    28549,
    29260,
    29261,
    29263,
    38274,
    40091,
    42333,
    43896,
    43897,
    43898,
    43899,
    43900,
    43901
  );
  script_xref(name:"VMSA", value:"2008-0005");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2008-0005)");
  script_summary(english:"Checks vulnerable versions of multiple VMware products");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues.");
  script_set_attribute(attribute:"description", value:
"VMware products installed on the remote host are affected by multiple
vulnerabilities :

  - The 'authd' process is affected by a privilege
    escalation vulnerability that could allow an attacker to
    execute arbitrary code with system level privileges or
    cause a denial of service condition.

  - A feature in VMware workstation version 6.0.2 could
    allow anonymous console access to guest host via VIX
    API, which could result in unauthorized access. This
    feature has been disabled in version 6.0.3.

  - Windows based VMware hosts are affected by a privilege
    escalation vulnerability. By manipulating 'config.ini'
    an attacker may be able to gain elevated privileges by
    hijacking the VMware VMX process.

  - Multiple VMware products are affected by a directory
    traversal vulnerability. If a Windows based VMware host
    is configured to allow shared access from a guest host
    to a folder on the Host system (HGFS), it may be
    possible
    to gain access to the Host file system from guest OS and
    create/modify arbitrary executable files. VMware Server
    is not affected by this vulnerability.

  - Multiple VMware products hosted on a Windows 2000 host
    are affected by a privilege escalation vulnerability.

  - Multiple VMware products are vulnerable to a potential
    denial of service attack.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0005.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/server/doc/releasenotes_server.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws6/doc/releasenotes_ws6.html#603" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws55/doc/releasenotes_ws55.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/player/doc/releasenotes_player.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/player2/doc/releasenotes_player2.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ace2/doc/releasenotes_ace2.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.0.3/5.5.6 or higher.
  - VMware Server 1.0.5 or higher.
  - VMware Player 2.0.3/1.0.6 or higher.
  - VMware ACE 2.0.3/1.0.5 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16, 20, 22, 264, 310, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

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
     ( int(v[0]) == 5 && int(v[1]) == 5 && int(v[2]) < 6 ) ||
     ( int(v[0]) == 6 && int(v[1]) == 0 && int(v[2]) < 3 )
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
      ( int(v[0]) == 1  && int(v[1]) == 0 && int(v[2]) < 5 )
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
      ( int(v[0]) == 2  && int(v[1]) == 0 && int(v[2]) < 3 )
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
 if ( ( int(v[0]) < 1 ) ||
    ( int(v[0]) == 1  && int(v[1]) == 0 && int(v[2]) < 5 ) ||
    ( int(v[0]) == 2  && int(v[1]) == 0 && int(v[2]) < 3 )
  )
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
