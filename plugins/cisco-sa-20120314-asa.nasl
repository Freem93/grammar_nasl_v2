#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58831);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id(
    "CVE-2012-0353",
    "CVE-2012-0354",
    "CVE-2012-0355",
    "CVE-2012-0356"
  );
  script_bugtraq_id(52482, 52484, 52488, 52489);
  script_osvdb_id(80041, 80043, 80044, 80045);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq10441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr47517");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts39634");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw35765");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120314-asa");

  script_name(english:"Cisco ASA 5500 Series Multiple Vulnerabilities (cisco-sa-20120314-asa)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA is missing a security patch and may be affected
by the following issues :

  - When UDP inspection is enabled, inspecting malformed
    transit traffic could cause the device to reload.
    (CVE-2012-0353)

  - When the Threat Detection feature is configured with the
    Scanning Threat Mode feature and the 'shun' option is
    enabled, unspecified transit traffic could cause the device
    to reload. (CVE-2012-0354)

  - A vulnerability in syslog could result in a device reload if
    specially crafted transit traffic is received. (CVE-2012-0355)

  - When multicast routing is enabled, processing a specially
    crafted Protocol Independent Multicast (PIM) message
    can cause the device to reload. (CVE-2012-0356)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fd78701");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120314-asa."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/14");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");
  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500');

# first check 7.0 and 7.1 (the recommendation is to migrate to 7.2 and upgrade)
if (ver =~ '^7\\.0($|[^0-9])' || ver =~ '^7\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Recommended release     : 7.2(5.7)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# then check 8.0 and 8.1 (the recommendation is to migrate to 8.2 or later and upgrade)
if (ver =~ '^8\\.0($|[^0-9])' || ver =~ '^8\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Recommended release     : 8.2(5.26)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all recommended releases.  The comparison is only made if the major versions match up
recommended_releases = make_list('7.2(5.7)', '8.2(5.20)', '8.3(2.29)', '8.4(3)', '8.5(1.6)', '8.6(1.1)');
foreach patch (recommended_releases)
{
  if (check_asa_release(version:ver, patched:patch))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + patch + '\n';
    security_hole(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);

