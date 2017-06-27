#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18365);
  script_version("$Revision: 1.24 $");

  script_cve_id("CVE-2005-1380", "CVE-2005-1742", "CVE-2005-1743", "CVE-2005-1744",
                "CVE-2005-1745", "CVE-2005-1746", "CVE-2005-1747", "CVE-2005-1748", "CVE-2005-1749");
  script_bugtraq_id(12548, 13400, 13717, 13793, 13794, 14632, 14657);
  script_osvdb_id(
    15895,
    16833,
    16834,
    16835,
    16836,
    16837,
    16838,
    16839,
    16840,
    16844,
    19158
  );

  script_name(english:"BEA WebLogic <= 8.1 SP4 Multiple Vulnerabilities (XSS, DoS, ID, more)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of BEA
WebLogic Server or WebLogic Express that is prone to multiple
vulnerabilities.  These flaws could lead to buffer overflows, denial
of service, unauthorized access, cross-site scripting attacks, and
information disclosure." );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070211133850/dev2dev.bea.com/pub/advisory/125" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070211133850/dev2dev.bea.com/pub/advisory/126" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070211133850/dev2dev.bea.com/pub/advisory/127" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070211133850/dev2dev.bea.com/pub/advisory/128" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070211133850/dev2dev.bea.com/pub/advisory/129" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070404224518/dev2dev.bea.com/pub/advisory/130" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070404224518/dev2dev.bea.com/pub/advisory/132" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070404224518/dev2dev.bea.com/pub/advisory/135" );
 script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20070404224518/dev2dev.bea.com/pub/advisory/137" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate Service Pack as discussed in the vendor
advisories referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/25");
 script_cvs_date("$Date: 2015/02/02 19:32:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in BEA WebLogic <= 8.1 SP4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Check the version number in the banner.
banner = get_http_banner(port:port);
if (!banner || "WebLogic " >!< banner) exit(0);

pat = "^Server:.*WebLogic .*([0-9]+\.[0-9.]+) ";
matches = egrep(pattern:pat, string:banner);
if (matches) {
  foreach match (split(matches, keep:FALSE)) {
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      # Extract the version and service pack numbers.
      nums = split(ver[1], sep:".", keep:FALSE);
      ver_maj = int(nums[0]);
      ver_min = int(nums[1]);

      sp = ereg_replace(
        string:match, 
        pattern:".* (Service Pack |SP)([0-9]+) .+",
        replace:"\2"
      );
      if (!sp) sp = 0;
      else sp = int(sp);

      # Check them against vulnerable versions listed in BEA's advisories.
      if (
        # version 6.x
        (
          ver_maj == 6 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 7)
          )
        ) ||

        # version 7.x
        (ver_maj == 7 && (ver_min == 0 && sp <= 6)) ||
  
        # version 8.x
        (
          ver_maj == 8 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 4)
          )
        )
      ) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      }
      exit(0);
    }
  }
}
