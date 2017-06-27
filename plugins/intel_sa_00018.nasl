#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(40458);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(35861);
  script_osvdb_id(57244);

  script_name(english:"Intel System Management Mode Local Privilege Escalation (INTEL-SA-00018)");
  script_summary(english:"Check Intel BIOS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is vulnerable to a local privilege escalation attack."
  );
  script_set_attribute( attribute:"description", value:
"The version of the Intel BIOS on the remote host is vulnerable to an
unspecified privilege escalation attack.  Software running in ring 0
could potentially change code running in System Management Mode (SMM).

SMM is a privileged operating system that runs independently from the
system's operating system.  A local attacker could exploit this to
run malicious code that may be undetectable from the operating system."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4890543e"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant BIOS firmware referenced in the vendor's
advisory."  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute( attribute:'vuln_publication_date', value:'2009/07/29' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/07/29' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/07/31' );
 script_cvs_date("$Date: 2011/03/21 01:56:46 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
  script_require_keys("BIOS/Version", "BIOS/Vendor");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


vendor = get_kb_item("BIOS/Vendor");
if (isnull(vendor)) exit(1, "No BIOS vendor found in the KB.");
if (vendor !~ "^Intel ") exit(0, "The BIOS vendor isn't Intel.");

version = get_kb_item("BIOS/Version");
if (isnull(version)) exit(0, "NO BIOS version found in the KB.");

# Determine if the host is using desktop or server firmware
# (Desktop = 86A or 86I followed by a 4 digit number. There may or may not be
# more fields after the four digit number.)
if (version =~ "\.86[AI]\.\d{4}(\..*)?$")
{
  # Intel Desktop board updates
  # The BIOS version is the 4 digit number after 86A or 86I
  # e.g.: APQ4310H.86A.0025 => version is 0025
  ver_idx = 2;
  updates = make_list(
    "APQ4310H.86A.0025",
    "BTX3810J.86A.2000",
    "CBQ4510H.86A.0087",
    "DPP3510J.86A.0572",
    "IDG4510H.86A.0105",
    "JOQ3510J.86A.1108",
    "JT94510H.86A.0032",
    "LDB4310H.86A.0031",
    "LF94510J.86A.0183",
    "MJG4110H.86A.0004",
    "NBG4310H.86A.0087",
    "RQG4110H.86A.0011",
    "SGP4510H.86A.0118",
    "SOX5810J.86A.4196",
    "TYG4110H.86A.0030",
    "XS54010J.86A.1338"
  );
}
else
{
  # Intel Server board updates
  # The BIOS version is the 4 digit number before the date code
  # e.g.: 3200X38.86B.00.00.0049.06162009 => version is 0049
  ver_idx = 4;
  updates = make_list(
    "3200X38.86B.00.00.0049.06162009",
    "S3000.86B.02.00.0054.06122009",
    "S5000.86B.12.00.0098.06232009",
    "S5400.86B.06.00.0032.070620091931",
    "S5500.86B.01.00.0037.05052009",
    "SFC4UR.86B.01.00.0029"
  );
}

# In the Intel advisory it's unclear if all unpatched version strings will
# be in the same format specified in the advisory (i.e. same number of fields).
# This assumes fields will at least be in the same order as the advisory
v = split(version, sep: '.', keep: 0);
if (max_index(v) - 1 < ver_idx)
  exit(1, "Unrecognized version format: " + version);

curr_ver = int(v[ver_idx]);

foreach u (updates)
{
  w = split(u, sep: '.', keep: 0);
  patched_ver = int(w[ver_idx]);

  # Checks the first field to see if it's the same firmware type, then compares
  # versions
  if (
    v[0] == w[0] &&
    curr_ver < patched_ver
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "  Current firmware version    : ", version, "\n",
        "  Upgrade to firmware version : ", u, "\n"
      );
      security_warning(port:0, extra:report);
    }
    else security_warning(0);

    exit(0);
  }
}

exit(0, "Version " + version + " isn't affected.");
