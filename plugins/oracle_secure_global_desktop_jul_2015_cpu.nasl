#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84795);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id(
    "CVE-2010-1324",
    "CVE-2015-1803",
    "CVE-2014-8102",
    "CVE-2015-0255",
    "CVE-2015-0286",
    "CVE-2014-0230",
    "CVE-2014-0227",
    "CVE-2014-3571",
    "CVE-2015-2581"
  );
  script_bugtraq_id(
    45116,
    71608,
    71937,
    72578,
    72717,
    73225,
    73280,
    74475,
    75901
  );
  script_osvdb_id(
    69609,
    115613,
    116793,
    118214,
    118221,
    119642,
    119761,
    120539,
    124734
  );

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle Secure Global Desktop installed on the remote host is
version 4.63 / 4.71 / 5.1 / 5.2. It is, therefore, affected by the
following vulnerabilities :

  - A security bypass vulnerability exists in Kerberos 5 due
    to a failure to properly determine the acceptability of
    checksums. A remote attacker can exploit this to forge
    tokens or gain privileges by using an unkeyed checksum.
    (CVE-2010-1324)

  - A NULL pointer deference flaw exists in the function
    bdfReadCharacters() in file bdfread.c of the X.Org
    libXfont module due to improper handling of non-readable
    character bitmaps. An authenticated, remote attacker,
    using a crafted BDF font file, can exploit this to
    cause a denial of service or execute arbitrary code.
    (CVE-2015-1803)

  - An out-of-bounds read/write error exists in the
    SProcXFixesSelectSelectionInput() function in the
    XFixes extension. A remote, authenticated attacker,
    using a crafted length value, can exploit this to
    cause a denial of service or execute arbitrary code.
    (CVE-2014-8102)

  - A remote attacker, by using a crafted string length
    value in an XkbSetGeometry request, can gain access to
    sensitive information from process memory or cause a
    denial of service. (CVE-2015-0255)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A denial of service vulnerability exists in Apache
    Tomcat due to improper handling of HTTP responses
    that occurs before finishing reading an entire request
    body. A remote attacker can exploit this by using a
    crafted series of aborted upload attempts.
    (CVE-2014-0230)

  - A denial of service vulnerability exists in Apache
    Tomcat in ChunkedInputFilter.java due to improper
    handling of attempts to read data after an error has
    occurred. A remote attacker can exploit this by
    streaming data with malformed chunked-transfer
    encoding. (CVE-2014-0227)

  - A NULL pointer dereference flaw exists in the
    dtls1_get_record() function when handling DTLS messages.
    A remote attacker, using a specially crafted DTLS
    message, can cause a denial of service. (CVE-2014-3571)

  - An unspecified flaw exists that is related to the
    JServer subcomponent. A remote attacker can exploit this
    to impact confidentiality and integrity. No further
    details have been provided. (CVE-2015-2581)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Oracle Secure Global Desktop";
version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

fix_required = NULL;

if (version =~ "^5\.20($|\.)") fix_required = 'Patch_52p1';
else if (version =~ "^5\.10($|\.)") fix_required = 'Patch_51p7';
else if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p7';
else if (version =~ "^4\.63($|\.)") fix_required = 'Patch_463p7';

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
{
  if (patch == fix_required)
  {
    patched = TRUE;
    break;
  }
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + fix_required + ')');

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Patch required    : ' + fix_required +
           '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
