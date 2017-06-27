#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36117);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2008-3761",
    "CVE-2008-4916",
    "CVE-2009-0177",
    "CVE-2009-0518",
    "CVE-2009-0908",
    "CVE-2009-0909",
    "CVE-2009-0910",
    "CVE-2009-1146",
    "CVE-2009-1147",
    "CVE-2009-1244",
    "CVE-2009-1805"
  );
  script_bugtraq_id(34373, 34471, 35141);
  script_osvdb_id(
    48051,
    51180,
    53409,
    53634,
    53694,
    53695,
    53696,
    54922,
    55942,
    55943,
    56409
  );
  script_xref(name:"VMSA", value:"2009-0005");
  script_xref(name:"VMSA", value:"2009-0006");
  script_xref(name:"VMSA", value:"2009-0007");
  script_xref(name:"EDB-ID", value:"6262");
  script_xref(name:"EDB-ID", value:"7647");
  script_xref(name:"Secunia", value:"33372");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2009-0005/VMSA-2009-0007)");
  script_summary(english:"Checks vulnerable versions of multiple VMware products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
issues.");
  script_set_attribute(attribute:"description", value:
"VMware products installed on the remote host are reportedly affected
by multiple vulnerabilities :

  - A vulnerability in the guest virtual device driver could
    allow an attacker to use the guest operating system to
    crash the host operating system. (CVE-2008-3761)

  - A denial of service vulnerability affects an unspecified
    IOCTL contained in the 'hcmon.sys' driver. An attacker
    can exploit this in order to deny service on a Windows-
    based host. (CVE-2009-1146, CVE-2008-3761)

  - A privilege escalation vulnerability affects the
    'vmci.sys' driver on Windows-based machines. An attacker
    can exploit this in order to gain escalated privileges
    on either the host or the guest. (CVE-2009-1147)

  - The 'VNnc' codec is affected by two heap-based buffer
    overflow vulnerabilities. An attacker can exploit these
    to execute arbitrary code on VMware hosted products by
    tricking a user into opening a malicious file.
    (CVE-2009-0909, CVE-2009-0910)

  - A vulnerability in ACE shared folder may allow attackers
    to enable previously disabled shared ACE folders. This
    only affects VMware ACE. (CVE-2009-0908)

  - A remote denial of service vulnerability affects Windows
    hosts. An attacker can exploit this to crash the
    affected host. (CVE-2009-0177)

  - A vulnerability in the virtual machine display function
    may allow a guest operating system to run code on the
    host. (CVE-2009-1244)

  - A vulnerability in VMware Descheduled Time Accounting
    Service could be exploited to trigger a denial of
    service condition in Windows-based virtual machines. It
    should be noted that, this feature is optional, and
    the vulnerability can be exploited only if the feature
    is installed, and the affected service is not running in
    the virtual machine. (CVE-2009-1805)");

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0005.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0006.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0007.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws65/doc/releasenotes_ws652.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/player25/doc/releasenotes_player252.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ace25/doc/releasenotes_ace252.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/server2/doc/releasenotes_vmserver201.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.5.2 or higher.
  - VMware Server 2.0.1/1.0.9 or higher.
  - VMware Player 2.5.2 or higher.
  - VMware ACE 2.5.2 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-757");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119, 200, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl","vmware_server_win_detect.nasl", "vmware_player_detect.nasl", "vmware_ace_detect.nasl");
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

 if (( int(v[0]) < 6 ) ||
     ( int(v[0]) == 6 && int(v[1]) < 5) ||
     ( int(v[0]) == 6 && int(v[1]) == 5 && int(v[2]) < 2)
   )
     {
       if (report_verbosity > 0)
       {
         report = string(
           "\n",
           "Version ", version," of VMware Workstation is installed on the remote host.",
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
  if ((int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) < 1) ||
      (
        int(v[0]) < 1 ||
        (
          int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 9
        )
      )
     )
     {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ", version," of VMware Server is installed on the remote host.",
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
  if (( int(v[0]) < 2 ) ||
      ( int(v[0]) == 2 && int(v[1]) < 5) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 2)
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ", version," of VMware Player is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
      }
      else
        security_hole(port);
    }
}

#Check for VMware ACE
version = get_kb_item("VMware/ACE/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if (( int(v[0]) < 2) ||
      ( int(v[0]) == 2 && int(v[1]) < 5 ) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 2 )
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ", version," of VMware ACE is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
      }
      else
        security_hole(port);
    }
}
