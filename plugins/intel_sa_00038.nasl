#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76117);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/18 11:36:23 $");

  script_cve_id("CVE-2014-2961");
  script_bugtraq_id(67947);
  script_osvdb_id(107519);

  script_name(english:"Intel Multiple Products Crafted UEFI Variable Handling Security Bypass");
  script_summary(english:"Checks BIOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Intel BIOS on the remote device is affected by an
unspecified security bypass vulnerability related to a flaw in the
handling of certain Unified Extensible Firmware Interface (UEFI)
variables.

A knowledgeable remote malicious attacker may be able to exploit this
issue to bypass security features or deny service to legitimate users.");
  # https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00038&languageid=en-fr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30bc64ce");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant BIOS firmware referenced in the vendor's
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:bios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
  script_require_keys("BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

vendor = get_kb_item_or_exit("BIOS/Vendor");
if (vendor !~ "^Intel($| )") exit(0, "The BIOS vendor is not Intel.");

version = get_kb_item_or_exit("BIOS/Version");

if (version =~ "^[^.]+\.86A\.\d{4}\.")
{
  # Intel Desktop board updates
  # The BIOS version is the 4 digit number after 86A or 86I
  # e.g.: APQ4310H.86A.0025 => version is 0025
  ver_idx = 2;
  updates = make_list(
    "WYLPT10H.86A.0026.2014.0514.1714",
    "FYBYT10H.86A.0034.2014.0513.1413",
    "TYBYT10H.86A.0024.2014.0523.1509",
    "RKPPT10H.86A.0033.2014.0519.1931"
  );
}
else if (version =~ "^[^.]+\.86B\.\d{2}\.\d{2}\.\d{4}(\.|$)")
{
  # Intel Server board updates
  # BIOS version is 4 digit string before timestamp
  ver_idx = 4;
  updates = make_list(
    "S1200RP.86B.02.01.0004.051320141432",
    "SE5C600.86B.02.02.0004.050520141103",
    "SE5C600.86B.02.03.0003.041920141333",
    "S1200BT.86B.02.00.0042.050820141549",
    "S3420GP.86B.01.00.0052.051620141",
    "S5500.86B.01.00.0064.05052014142"
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Intel BIOS", version);

# In the Intel advisory it's unclear if all unpatched version strings will
# be in the same format specified in the advisory (i.e. same number of fields).
# This assumes fields will at least be in the same order as the advisory
v = split(version, sep: '.', keep: 0);
if (max_index(v) - 1 < ver_idx)
  exit(1, "Unrecognized version format : " + version);

curr_ver = int(v[ver_idx]);

curr_prefix = '';
for (i=0; i < ver_idx; i++) curr_prefix += v[i];

foreach u (updates)
{
  w = split(u, sep: '.', keep: 0);

  patched_prefix = '';
  for (i=0; i < ver_idx; i++) patched_prefix += w[i];

  if (patched_prefix != curr_prefix) continue;

  patched_ver = int(w[ver_idx]);

  if (curr_ver < patched_ver)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Current firmware version    : ' + version +
        '\n  Upgrade to firmware version : ' + u + '\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);

    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, "Intel BIOS", version);
