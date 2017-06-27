#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92723);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/06 20:05:59 $");

  script_cve_id("CVE-2016-6258", "CVE-2016-6259");
  script_bugtraq_id(92130, 92131);
  script_osvdb_id(142101, 142140);
  script_xref(name:"IAVB", value:"2016-B-0118");

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX214954) (Bunker Buster)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A privilege escalation vulnerability known as 'Bunker
    Buster' exists in the paravirtualization (PV) pagetable
    implementation due to incorrect usage of fast-paths for
    making updates to pre-existing pagetable entries. An
    attacker with administrative privileges on a PV guest
    can exploit this vulnerability to gain administrative
    privileges on the host operating system. This
    vulnerability only affects PV guests on x86 hardware;
    HVM and ARM guests are not affected. (CVE-2016-6258)

  - A denial of service vulnerability exists when handling
    32-bit exceptions and event delivery due to missing SMAP
    whitelisting. A local guest attacker can exploit this to
    trigger a safety check that will crash other virtual
    machines on the host system. This vulnerability only
    exists on 32-bit PV guests running on x86 hardware that
    supports SMAP. (CVE-2016-6259)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX214954");
  # https://www.scmagazine.com/xen-hypervisor-vulnerability-found/article/529945/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e5f1cb7");
  # https://nakedsecurity.sophos.com/2016/07/28/the-xen-bunker-buster-bug-what-you-need-to-know/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83872af7");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/07/26");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

if (version == "6.0.0")
{
  fix = "XS60E062";
  if (fix >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E056 or XS602ECC033";
  if (("XS602E056" >!< patches) && ("XS602ECC033" >!< patches)) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E071";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1045";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1034";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E008";
  if (fix >!< patches) vuln = TRUE;
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
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
