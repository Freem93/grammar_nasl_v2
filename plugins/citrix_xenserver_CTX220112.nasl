#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96928);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/06 15:01:21 $");

  script_cve_id(
    "CVE-2015-5300",
    "CVE-2015-7704",
    "CVE-2015-7705",
    "CVE-2017-5572",
    "CVE-2017-5573"
  );
  script_bugtraq_id(
    77280,
    77284,
    77312,
    95796,
    95801
  );
  script_osvdb_id(
    129309,
    129310,
    129315,
    150974,
    150975
  );
  script_xref(name:"CERT", value:"718152");

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX220112)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by the following
vulnerabilities :

  - A man-in-the-middle (MitM) vulnerability exists in the
    NTP component due to an improperly implemented threshold
    limitation for the '-g' option. A man-in-the-middle
    attacker can exploit this to intercept NTP traffic and
    return arbitrary date and time values to users. This
    vulnerability is only applicable if NTP is enabled.
    (CVE-2015-5300)

  - A denial of service vulnerability exists in the NTP
    component due to improper validation of the origin
    timestamp field when handling a Kiss-of-Death (KoD)
    packet. An unauthenticated, remote attacker can exploit
    this to cause a client to stop querying its servers,
    preventing the client from updating its clock. This
    vulnerability is only applicable if NTP is enabled.
    (CVE-2015-7704)

  - A denial of service vulnerability exists in the NTP
    component due to improper implementation of
    rate-limiting when handling server queries. An
    unauthenticated, remote attacker can exploit this to
    stop the client from querying its servers, preventing it
    from updating its clock. This vulnerability is only
    applicable if NTP is enabled. (CVE-2015-7705)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker with read-only administrator access to
    corrupt the host database. This vulnerability is only
    applicable if RBAC is enabled. (CVE-2017-5572)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker with read-only administration access to
    cancel the tasks of other administrators. This
    vulnerability is only applicable if RBAC is enabled.
    (CVE-2017-5573)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX220112");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/10/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

if (version == "6.0.2")
{
  fix = "XS602ECC036"; # CTX220078
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1051 and XS62ESP1055"; # CTX220079 and CTX220242
  if (("XS62ESP1051" >!< patches) || ("XS62ESP1055" >!< patches)) vuln = TRUE;
}
else if (version =~ "^6\.5\.0")
{
  fix = "XS65ESP1040 and XS65ESP1047"; # CTX220080 and CTX220243
  if (("XS65ESP1040" >!< patches) || ("XS65ESP1047" >!< patches)) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E018"; # CTX220081 and CTX220244
  if (("XS70E018" >!< patches) || ("XS70E025" >!< patches)) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Missing hotfix", fix
    ),
    ordered_fields:make_list("Installed version", "Missing hotfix")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
