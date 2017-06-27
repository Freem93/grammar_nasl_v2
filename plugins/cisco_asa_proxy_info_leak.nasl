#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59227);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/02/05 16:07:42 $");

  script_cve_id("CVE-2012-0335");
  script_bugtraq_id(53558);
  script_osvdb_id(81856);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx42746");

  script_name(english:"Cisco ASA Cut Through Proxy Authentication Vulnerability");
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
by an information disclosure vulnerability.  Requesting a resource
behind the firewall causes the device to prompt the user for their
credentials on a page served over HTTPS.  This page contains a
session ID."
  );
  # http://www.cisco.com/web/software/280775065/89203/ASA-843-Interim-Release-Notes.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?a40f8997");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant patch referenced in the bug details for CSCtx42746."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/03/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:asa_5500");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

# 7.2 is listed as vulnerable, but there is no 7.2 fix listed
if (ver =~ '^7\\.2($|[^0-9])')
{
  report =
    '\n  Installed release   : ' + ver +
    '\n  Recommended release : 8.4(3.4)\n';
  security_warning(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all recommended releases.  The comparison is only made if the major versions match up
recommended_releases = make_list('8.2(5.25)', '8.4(3.4)', '8.5(1.8)');
foreach patch (recommended_releases)
{
  if (check_asa_release(version:ver, patched:patch))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + patch + '\n';
    security_warning(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);
