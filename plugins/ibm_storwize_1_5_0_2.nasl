#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84401);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 16:23:37 $");

  script_cve_id(
    "CVE-2007-6750",
    "CVE-2013-4286",
    "CVE-2013-4322",
    "CVE-2014-0075",
    "CVE-2014-0094",
    "CVE-2014-0096",
    "CVE-2014-0099",
    "CVE-2014-0119",
    "CVE-2014-0178",
    "CVE-2014-1555",
    "CVE-2014-1556",
    "CVE-2014-1557",
    "CVE-2014-3077",
    "CVE-2014-3493",
    "CVE-2014-4811"
  );
  script_bugtraq_id(
    21865,
    65767,
    65773,
    65999,
    67667,
    67668,
    67669,
    67671,
    67686,
    68150,
    68814,
    68822,
    68824,
    69771,
    69773
  );
  script_osvdb_id(
    103706,
    103708,
    103918,
    107450,
    107452,
    107453,
    107475,
    107485,
    108347,
    109432,
    109433,
    109434,
    110681,
    111380,
    121361
  );
  script_xref(name:"CERT", value:"719225");
  script_xref(name:"IAVB", value:"2015-B-0083");

  script_name(english:"IBM Storwize 1.3.x < 1.4.3.4 / 1.5.x < 1.5.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for vulnerable Storwize versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote IBM Storwize device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote IBM Storwize device is running a version that is 1.3.x
prior to 1.4.3.4 or 1.5.x prior to 1.5.0.2. It is, therefore, affected
by multiple vulnerabilities :

  - A denial of service vulnerability exists due to a flaw
    in the bundled version of Apache HTTP Server. A remote
    attacker can exploit this, via partial HTTP requests,
    to cause a daemon outage, resulting in a denial of
    service condition. (CVE-2007-6750)

  - An HTTP request smuggling vulnerability exists due to a
    flaw in the bundled version of Apache Tomcat; when an
    HTTP connector or AJP connector is used, Tomcat fails to
    properly handle certain inconsistent HTTP request
    headers. A remote attacker can exploit this flaw, via
    multiple Content-Length headers or a Content-Length
    header and a 'Transfer-Encoding: chunked' header, to
    smuggle an HTTP request in one or more Content-Length
    headers. (CVE-2013-4286)

  - A denial of service vulnerability exists in the bundled
    version of Apache Tomcat due to improper processing of
    chunked transfer coding with a large amount of chunked
    data or whitespace characters in an HTTP header value
    within a trailer field. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2013-4322)

  - A denial of service vulnerability exists due to a flaw
    in the bundled version of Apache Tomcat; an integer
    overflow condition exists in the parseChunkHeader()
    function in ChunkedInputFilter.java. A remote attacker
    can exploit this, via a malformed chunk size that is
    part of a chunked request, to cause excessive
    consumption of resources, resulting in a denial of
    service condition. (CVE-2014-0075)

  - A remote code execution vulnerability exists due to a
    flaw in the bundled version of Apache Struts. A remote
    attacker can manipulate the ClassLoader via the class
    parameter, resulting in the execution of arbitrary Java
    code. (CVE-2014-0094)

  - An XML External Entity (XXE) injection vulnerability
    exists due to a flaw in the bundled version of Apache
    Tomcat; an incorrectly configured XML parser accepts
    XML external entities from an untrusted source via XSLT.
    A remote attacker can exploit this, by sending specially
    crafted XML data, to gain access to arbitrary files.
    (CVE-2014-0096)

  - An integer overflow condition exists in the bundled
    version of Apache Tomcat. A remote attacker, via a
    crafted Content-Length HTTP header, can conduct HTTP
    request smuggling attacks. (CVE-2014-0099)

  - An information disclosure vulnerability exists due to a
    flaw in the bundled version of Apache Tomcat. Tomcat
    fails to properly constrain the class loader that
    accesses the XML parser used with an XSLT stylesheet. A
    remote attacker can exploit this, via a crafted web
    application that provides an XML external entity
    declaration in conjunction with an entity reference, to
    read arbitrary files. (CVE-2014-0119)

  - A flaw exists in a bundled version of Samba due to a
    flaw in the vfswrap_fsctl() function that is triggered
    when responding to FSCTL_GET_SHADOW_COPY_DATA or
    FSCTL_SRV_ENUMERATE_SNAPSHOTS client requests. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted request, to disclose sensitive
    information from process memory. (CVE-2014-0178)

  - Multiple flaws exist in the bundled version of Mozilla
    Firefox that allow a remote attacker to execute
    arbitrary code. (CVE-2014-1555, CVE-2014-1556,
    CVE-2014-1557)

  - An information disclosure vulnerability exists due to
    the chkauth password being saved in plaintext in the
    audit log. A local attacker can exploit this to gain
    administrator access. (CVE-2014-3077)

  - A denial of service vulnerability exists due to a flaw
    in the bundled version of Samba. An authenticated,
    remote attacker can exploit this, via an attempt to read
    a Unicode pathname without specifying the use of
    Unicode, to cause an application crash. (CVE-2014-3493)
  
  - A security bypass vulnerability exists due to an
    unspecified flaw. A remote attacker can exploit this
    flaw to reset the administrator password to its default
    value via a direct request to the administrative IP
    address. Note that this vulnerability only affects the
    1.4.x release levels. (CVE-2014-4811)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004834");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004836");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004837");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004854");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004860");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004861");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004867");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004869");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004835");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Storwize version 1.4.3.4 / 1.5.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_unified_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v3700");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v3500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:san_volume_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v7000_unified_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v7000_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v5000_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v3700_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v3500_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:san_volume_controller_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_storwize_detect.nbin");
  script_require_keys("Host/IBM/Storwize/version", "Host/IBM/Storwize/machine_major", "Host/IBM/Storwize/display_name");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/IBM/Storwize/version");
machine_major = get_kb_item_or_exit("Host/IBM/Storwize/machine_major");
display_name = get_kb_item_or_exit("Host/IBM/Storwize/display_name");

if (
  machine_major != "2073" && # V7000 Unified
  machine_major != "2071" && # V3500
  machine_major != "2072" && # V3700
  machine_major != "2076" && # V7000
  machine_major != "2077" && # V5000
  machine_major != "2145" && # SAN Volume Controller
  machine_major != "4939"    # Flex System V7000 Storage Node
) audit(AUDIT_DEVICE_NOT_VULN, display_name);

if (version == UNKNOWN_VER || version == "Unknown")
  audit(AUDIT_UNKNOWN_APP_VER, display_name);

if (machine_major == "2073")
{
  if (version =~ "^1\.[3-4]\.") fix = "1.4.3.4";
  else if (version =~ "^1\.5\.") fix = "1.5.0.2";
  else audit(AUDIT_DEVICE_NOT_VULN, display_name, version);
}
else
{
  if (version =~ "^((6\.[1234])|(7\.[12]))\.") fix = "7.2.0.8";
  else if (version =~ "^7\.3\.") fix = "7.3.0.5";
  else audit(AUDIT_DEVICE_NOT_VULN, display_name, version);
}

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_DEVICE_NOT_VULN, display_name, version);

if (report_verbosity > 0)
{
  report =
    '\n  Name              : ' + display_name +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(port:0);
