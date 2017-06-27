#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81167);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");

  script_name(english:"Palo Alto Networks PAN-OS <= 5.0.15 / 6.0.x <= 6.0.8 / 6.1.x <= 6.1.2 GNU C Library (glibc) Buffer Overflow (GHOST)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Palo Alto Networks PAN-OS
equal to or prior to 5.0.15 / 6.0.8 / 6.1.2. It is, therefore,
affected by a heap-based buffer overflow in the GNU C Library (glibc)
due to improperly validating user-supplied input in the glibc
functions __nss_hostname_digits_dots(), gethostbyname(), and
gethostbyname2(). This allows a remote attacker to cause a buffer
overflow, resulting in a denial of service condition or the execution
of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/29");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"The vendor has not yet provided a patch at this time (2015/03/10).

Please contact the vendor regarding a patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (
  version =~ "^5(\.0)?$" ||
  version =~ "^6(\.[01])?$"
) audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^6\.1\.")
  cutoff = "6.1.2";
else if (version =~ "^6\.0\.")
  cutoff = "6.0.8";
else if (
  version =~ "^[0-4]($|[^0-9])" ||
  version =~ "^5\.0\."
)
  cutoff = "5.0.15";
else
  audit(AUDIT_NOT_INST, app_name + " 0.x-4.x / 5.0.x / 6.0.x / 6.1.x");

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:cutoff, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : See solution.' +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
