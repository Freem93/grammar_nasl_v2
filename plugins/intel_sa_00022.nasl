#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44624);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2010-0560");
  script_bugtraq_id(38251);
  script_osvdb_id(62071);
  script_xref(name:"Secunia", value:"38413");

  script_name(english:"Intel Desktop Boards Privilege Escalation (INTEL-SA-00022)");
  script_summary(english:"Check Intel BIOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by a local privilege escalation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the Intel BIOS on the remote host is affected by an
unspecified privilege escalation vulnerability. 

A local attacker with administrative (ring 0) privileges could exploit
this to execute arbitrary code in System Management Mode (SMM)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?410c2374"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the relevant BIOS firmware referenced in the vendor's
advisory."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/01");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/16");
 script_cvs_date("$Date: 2011/03/21 01:56:46 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

 script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
 script_require_keys("BIOS/Version", "BIOS/Vendor", "BIOS/ReleaseDate");
 exit(0);
}

include("global_settings.inc");

vendor = get_kb_item("BIOS/Vendor");
if (isnull(vendor)) exit(1, "The 'BIOS/Vendor' KB item is missing.");
if (vendor !~ "^Intel ")  exit(0,"The BIOS vendor is not Intel.");

version = get_kb_item("BIOS/Version");
if (isnull(version)) exit(1, "The 'BIOS/Version' KB item is missing.");

updates = make_list(
  'APQ4310H.86A.0031',
  'CBQ4510H.86A.0109',
  'JOQ3510J.86A.1126',
  'KGIBX10J.86A.4236',
  'WBIBX10J.86A.0181',
  'TMIBX10H.86A.0025',
  'TCIBX10H.86A.0028',
  'KRG4110H.86A.0029',
  'LDB4310H.86A.0035',
  'MJG4110H.86A.0006',
  'RQG4110H.86A.0013',
  'TYG4110H.86A.0037',
  'SGP4510H.86A.0125',
  'NBG4310H.86A.0104',
  'GTG4310H.86A.0028'
);

v = split(version, sep: '.', keep:FALSE);
if (max_index(v) < 3)  exit(1,"max_index (v) < 3.");

foreach u (updates)
{
  w = split(u, sep: '.', keep: 0);

  if (v[0] == w[0] && v[1] == w[1] && int(v[2]) < int(w[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n'+
        '  Current firmware version    : '+version+'\n'+
        '  Upgrade to firmware version : '+u+'\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);
    exit(0);
  }
}
exit(0, "Installed Intel BIOS version '" + version + "' is not affected.");
