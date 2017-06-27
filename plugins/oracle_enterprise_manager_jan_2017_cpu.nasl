#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96777);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/21 16:53:27 $");

  script_cve_id("CVE-2015-7940", "CVE-2016-5019");
  script_bugtraq_id(79091, 93236);
  script_osvdb_id(129389, 144919);

  script_name(english:"Oracle Enterprise Manager Cloud Control Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in the
Enterprise Manager Base Platform component :

  - A flaw exists in the Bouncy Castle Java library due to
    improper validation of a point within the elliptic
    curve. An unauthenticated, remote attacker can exploit
    this to obtain private keys by using a series of
    specially crafted elliptic curve Diffie-Hellman (ECDH)
    key exchanges, also known as an 'invalid curve attack.'
    (CVE-2015-7940)

  - A flaw exists in Apache MyFaces Trinidad, specifically
    in the CoreResponseStateManager component, due to the
    ObjectInputStream and ObjectOutputStream strings being
    used directly without securely deserializing Java input.
    An unauthenticated, remote attacker can exploit this,
    via a deserialization attack using a crafted serialized
    view state string, to have an unspecified impact that
    may include the execution of arbitrary code.
    (CVE-2016-5019)

Note that the product was formerly known as Enterprise Manager Grid
Control.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0d463a2");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");

product = "Oracle Enterprise Manager Cloud Control";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patchid = NULL;
missing = NULL;
patched = FALSE;

if (version =~ "^13\.1\.0\.0(\.[0-9]+)?$")
  patchid = "24897689";
else if (version =~ "^12\.1\.0\.5(\.[0-9]+)?$")
  patchid = "24897692";

if (isnull(patchid))
  audit(AUDIT_HOST_NOT, 'affected');

# Now look for the affected components
patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));
if (isnull(patchesinstalled))
  missing = patchid;
else
{
  foreach applied (keys(patchesinstalled[emchome]))
  {
    if (applied == patchid)
    {
      patched = TRUE;
      break;
    }
    else
    {
      foreach bugid (patchesinstalled[emchome][applied]['bugs'])
      {
        if (bugid == patchid)
        {
          patched = TRUE;
          break;
        }
      }
      if (patched) break;
    }
  }
  if (!patched)
    missing = patchid;
}

if (empty_or_null(missing))
  audit(AUDIT_HOST_NOT, 'affected');

order = make_list('Product', 'Version', "Missing patch");
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
