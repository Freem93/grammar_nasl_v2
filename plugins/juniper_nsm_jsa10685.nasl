#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84877);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2008-0456",
    "CVE-2012-2687",
    "CVE-2012-3499",
    "CVE-2012-4558",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-6438",
    "CVE-2014-0098",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231"
  );
  script_bugtraq_id(
    27409,
    55131,
    58165,
    58165,
    59826,
    61129,
    66303,
    66303,
    68678,
    68742,
    68745
  );
  script_osvdb_id(
    41018,
    84818,
    90556,
    90557,
    93366,
    95498,
    104579,
    104580,
    109216,
    109231,
    109234
  );
  script_xref(name:"IAVA", value:"2015-A-0149");

  script_name(english:"Juniper NSM < 2012.2R9 Apache HTTP Server Multiple Vulnerabilities (JSA10685)");
  script_summary(english:"Checks the versions of NSM servers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of NSM (Network and Security
Manager) Server that is prior to 2012.2R9. It is, therefore, affected
by multiple vulnerabilities in the bundled version of Apache HTTP
Server :

  - A flaw exists due to improper escaping of filenames in
    406 and 300 HTTP responses. A remote attacker can
    exploit this, by uploading a file with a specially
    crafted name, to inject arbitrary HTTP headers or
    conduct cross-site scripting attacks. (CVE-2008-0456)

  - Multiple cross-site scripting vulnerabilities exist in
    the mod_negotiation module due to improper sanitization
    of input passed via filenames. An attacker can exploit
    this to execute arbitrary script code in a user's
    browser. (CVE-2012-2687)

  - Multiple cross-site scripting vulnerabilities exist in
    the mod_info, mod_status, mod_imagemap, mod_ldap, and
    mod_proxy_ftp modules due to improper validation of
    input passed via the URL or hostnames. An attacker can
    exploit this to execute arbitrary script code in a
    user's browser. (CVE-2012-3499)

  - A cross-site scripting vulnerability exists in the
    mod_proxy_balancer module due to improper validation of
    input passed via the URL or hostnames. An attacker can
    exploit this to execute arbitrary script code in a
    user's browser. (CVE-2012-4558)

  - A flaw exists in the do_rewritelog() function due to
    improper sanitization of escape sequences written to log
    files. A remote attacker can exploit this, via a
    specially crafted HTTP request, to execute arbitrary
    commands. (CVE-2013-1862)

  - A denial of service vulnerability exists in mod_dav.c
    due to improper validation to determine if DAV is
    enabled for a URI. A remote attacker can exploit this,
    via a specially crafted MERGE request, to cause a
    segmentation fault, resulting in a denial of service
    condition. (CVE-2013-1896)

  - A denial of service vulnerability exists in the
    dav_xml_get_cdata() function
    due to improper removal of whitespace characters from
    CDATA sections. A remote attacker can exploit this,
    via a specially crafted DAV WRITE request, to cause a
    daemon crash, resulting in a denial of service
    condition. (CVE-2013-6438)

  - A flaw exists in log_cookie() function due to the
    logging of cookies with an unassigned value. A remote
    attacker can exploit this, via a specially crafted
    request, to cause a segmentation fault, resulting in a
    denial of service condition. (CVE-2014-0098)

  - A flaw exists in the deflate_in_filter() function when
    request body decompression is configured. A remote
    attacker can exploit this, via a specially crafted
    request, to exhaust available memory and CPU resources,
    resulting in a denial of service condition.
    (CVE-2014-0118)

  - A race condition exists in the mod_status module due to
    improper validation of user-supplied input when handling
    the scoreboard. A remote attacker can exploit this, via
    a crafted request, to cause a heap-based buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2014-0226)

  - A flaw exists in the mod_cgid module due to the lack of
    a timeout mechanism. A remote attacker can exploit this,
    via a request to a CGI script that does not read from
    its stdin file descriptor, to cause a denial of service
    condition. (CVE-2014-0231)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10685");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper NSM version 2012.2R9 or later. Alternatively,
apply Upgrade Package v4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:network_and_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl","juniper_nsm_gui_svr_detect.nasl");
  script_require_keys("Juniper_NSM_VerDetected", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

kb_base = "Host/NSM/";

# Since we can't detect the package change remotely this needs to be paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Juniper_NSM_VerDetected");

kb_list = make_list();

temp = get_kb_list("Juniper_NSM_GuiSvr/*/build");

if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

temp = get_kb_list("Host/NSM/*/build");
if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

if (max_index(kb_list) == 0) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

report = '';

entry = branch(kb_list);

port = 0;
kb_base = '';

if ("Juniper_NSM_GuiSvr" >< entry)
{
  port = entry - "Juniper_NSM_GuiSvr/" - "/build";
  kb_base = "Juniper_NSM_GuiSvr/" + port + "/";

  report_str1 = "Remote GUI server version : ";
  report_str2 = "Fixed version             : ";
}
else
{
  kb_base = entry - "build";
  if ("guiSvr" >< kb_base)
  {
    report_str1 = "Local GUI server version : ";
    report_str2 = "Fixed version            : ";
  }
  else
  {
    report_str1 = "Local device server version : ";
    report_str2 = "Fixed version               : ";
  }
}

build = get_kb_item_or_exit(entry);
version = get_kb_item_or_exit(kb_base + 'version');

version_disp = version + " (" + build + ")";

# NSM 2012.2R9 or later
# replace r or R with . for easier version comparison
# in 2010 and 2011 versions they use S instead of R
version_num = ereg_replace(pattern:"(r|R|s|S)", replace:".", string:version);

# remove trailing . if it exists
version_num = ereg_replace(pattern:"\.$", replace:"", string:version_num);

fix_disp = "2012.2R9";
fix_num = "2012.2.9";
if (ver_compare(ver:version_num, fix:fix_num, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\n  ' + report_str1 + version_disp +
             '\n  ' + report_str2 + fix_disp +
             '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM", version_disp);
