#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42308);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-2267");
  script_bugtraq_id(36841);
  script_osvdb_id(59441);
  script_xref(name:"VMSA", value:"2009-0015");
  script_xref(name:"Secunia", value:"37172");

  script_name(english:"VMware Products Privilege Escalation Vulnerability (VMSA-2009-0015)");
  script_summary(english:"Checks vulnerable versions of multiple VMware products");

  script_set_attribute( attribute:"synopsis", value:
"The remote host has a virtualization application affected by a
privilege escalation vulnerability."  );
  script_set_attribute( attribute:"description", value:
"A VMware product (Workstation, Player, ACE, or Server) detected on
the remote host has a privilege escalation vulnerability.  Page
fault exceptions are not handled properly, which could allow a local
attacker to elevate privileges within the guest VM.  This
vulnerability reportedly does not affect the host system."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.vmware.com/security/advisories/VMSA-2009-0015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000069.html"
  );
  script_set_attribute( attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.5.3 or later.
  - VMware Server 2.0.2 / 1.0.10 or later.
  - VMware Player 2.5.3 or later.
  - VMware ACE 2.5.3 or later."  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/29"
  );
 script_cvs_date("$Date: 2015/01/29 00:33:21 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_server");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl","vmware_server_win_detect.nasl", "vmware_player_detect.nasl", "vmware_ace_detect.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();
report = "";
vuln = NULL;

# Check for VMware Workstation

version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if (( int(v[0]) < 6 ) ||
     ( int(v[0]) == 6 && int(v[1]) < 5) ||
     ( int(v[0]) == 6 && int(v[1]) == 5 && int(v[2]) < 3)
   )
 {
   vuln = TRUE;

   report = string(
     "\n",
     "Product           : VMware Workstation\n",
     "Installed version : ", version, "\n",
     "Fixed version     : 6.5.3\n"
   );
 }
 else if (isnull(vuln)) vuln = FALSE;
}

# Check for VMware Server

version = get_kb_item("VMware/Server/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if ((int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) < 2) ||
      (
        int(v[0]) < 1 ||
        (
          int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 10
        )
      )
     )    
  {
    vuln = TRUE;

    if ("1.0" >< version) fixed_ver = "1.0.10";
    else fixed_ver = "2.0.2";

    report = string(
      "\n",
      "Product           : VMware Server\n",
      "Installed version : ", version, "\n",
      "Fixed version     : ", fixed_ver, "\n"
    );
  }
  else if (isnull(vuln)) vuln = FALSE;
}

# Check for VMware Player

version = get_kb_item("VMware/Player/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if (( int(v[0]) < 2 ) ||
      ( int(v[0]) == 2 && int(v[1]) < 5) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 3)
    )
  {
    vuln = TRUE;
    report = string(
      "\n",
      "Product           : VMware Player\n",
      "Installed version : ", version, "\n",
      "Fixed version     : 2.5.3\n"
    );
  }
  else if (isnull(vuln)) vuln = FALSE;
}

# Check for VMware ACE.
version = get_kb_item("VMware/ACE/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if (( int(v[0]) < 2) ||
      ( int(v[0]) == 2 && int(v[1]) < 5 ) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 3 )
    )
  {
    vuln = TRUE;
    report = string(
      "\n",
      "Product           : VMware ACE\n",
      "Installed version : ", version, "\n",
      "Fixed version     : 2.5.3\n"
    );
  }
  else if (isnull(vuln)) vuln = FALSE;
}

if (isnull(vuln)) exit(0, "No VMware products were detected on this host.");
if (!vuln) exit(0, "The host is not affected.");

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole(port);

