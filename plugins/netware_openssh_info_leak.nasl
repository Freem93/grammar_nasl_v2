#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44064);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/09/27 14:13:10 $");

  script_cve_id("CVE-2004-2414");
  script_bugtraq_id(9934);
  script_osvdb_id(4514);
  script_xref(name:"Secunia", value:"11188");

  script_name(english:"Novell NetWare 6.5 Support Pack 1.1 Admin/Install Local Information Disclosure");
  script_summary(english:"Checks if 6.5 SP 1.1 and OpenSSH are installed");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the list of enumerated software packages, the version of
Novel NetWare installed on the remote host may have an information
disclosure vulnerability.  Admin/install passwords are stored in the
NIOUTPUT.TXT and NI.LOG installation log files.  A local attacker
could exploit this to gain access to sensitive information.

Systems are vulnerable if an installation/upgrade was performed using
the NetWare 6.5 Support Pack 1.1 Overlay CDs, and when the OpenSSH
component is selected during Custom Installation."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Use NetWare 6.5 Support Pack 1.1(b) for all future installations and
upgrades."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:netware:6.5:sp1.1a");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Netware");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("snmp_software.nasl");
  script_require_keys("SNMP/hrSWInstalledName", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# we don't know if SP1.1 and SP1.1(b) look identical in the SNMP sofware enumeration
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

sw = get_kb_list_or_exit("SNMP/hrSWInstalledName");
sw = make_list(sw);
ssh = FALSE;
nw6511 = FALSE;

foreach package (sw)
{
  if ('v1.1 Support Pack for NetWare 6.5' >< package)
    nw6511 = TRUE;
  if ('OpenSSH' >< package)
    ssh = TRUE;
}

if (!nw6511)
  exit(0, 'Netware 6.5 SP 1.1 doesn\'t appear to be installed.');
else if (!ssh)
  exit(0, 'OpenSSH doesn\'t appear to be installed.');
else
  security_note(0);

