#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92585);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/09 15:07:54 $");

  script_cve_id(
    "CVE-2016-2107",
    "CVE-2016-3540",
    "CVE-2016-3563"
  );
  script_bugtraq_id(
    89760,
    91880,
    91892
  );
  script_osvdb_id(
    137896,
    141744,
    141746
  );
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Oracle Enterprise Manager Cloud Control Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in the
Enterprise Manager Base Platform component :

  - Multiple flaws exist in the OpenSSL library bundled in
    the Discovery Framework subcomponent, specifically in
    the aesni_cbc_hmac_sha1_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha1.c and the
    aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c, that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - An unspecified flaw exists in the UI Framework
    subcomponent that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    (CVE-2016-3540)

  - An unspecified flaw exists in the Security Framework
    subcomponent that allows a local attacker to impact
    confidentiality and integrity. (CVE-2016-3563)

Note that the product was formerly known as Enterprise Manager Grid
Control.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b75e27b4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
fix     = NULL;
patchid = FALSE;

if (version =~ "^13\.1\.0\.0(\.[0-9]+)?$")
{
  fix = "13.1.0.0.160719"; 
  patchid = "23134365";
}
else if (version =~ "^12\.1\.0\.5(\.[0-9]+)?$")
{
  fix = "12.1.0.5.160719";
  patchid = "23087400";
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

# This patch doesn't appear in later patches' bug fixes but it is fixed
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

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
  audit(AUDIT_PATCH_INSTALLED, patchid, product, version);

order = make_list('Product', 'Version', "Missing patch");
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
