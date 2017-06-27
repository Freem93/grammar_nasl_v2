#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10815);
  script_version("$Revision: 1.89 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id(
    "CVE-2002-1060",
    "CVE-2002-1700",
    "CVE-2003-1543",
    "CVE-2005-2453",
    "CVE-2006-1681",
    "CVE-2012-3382"
  );
  script_bugtraq_id(
    5011,
    5305,
    7344,
    7353,
    8037,
    14473,
    17408,
    54344
  );
  script_osvdb_id(
    4989,
    18525,
    21557,
    24469,
    42314,
    58976,
    83683
  );

  script_name(english:"Web Server Generic XSS");
  script_summary(english:"Checks for generic cross-site scripting vulnerability in a web server.");


  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a web server that fails to adequately
sanitize request strings of malicious JavaScript. A remote attacker
can exploit this issue, via a specially crafted request, to execute
arbitrary HTML and script code in a user's browser within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross-site_scripting");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);

file = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789");
exts = make_list(
  "asp",
  "aspx",
  "pl",
  "cgi",
  "exe",
  "cfm",
  "html",
  "jsp",
  "php",
  "php3",
#  "phtml",
#  "shtml",
   "cfc",
   "nsf",
   "dll",
   "fts",
   "jspa",
   "kspx",
   "mscgi",
   "do",
   "htm",
   "idc",
   "x",
   ""
);
exploits = make_list(
  # nb: while this isn't valid JavaScript, it will tell us
  #     if malicious script tags are output unfiltered.
  "<script>" + SCRIPT_NAME + "</script>",
  '<IMG SRC="javascript:alert(' + SCRIPT_NAME + ');">'
);

hdrs = make_list(
  "Referer",
  "Cookie",
  "User-Agent",
  "Pragma",
  "Accept",
  "X-Forwarded-For",
  "Accept-Language",
  "Accept-Charset",
  "Expect",
  "Connection",
  "Host",
  "Content-Type",
  "Content-Length"
);

vuln_url = FALSE;
vuln_hdr = FALSE;

vuln = 0;
failures = 0;

dirs_l = NULL;
hdr_ext = NULL;
# If we are in paranoid mode, we want to reduce the FPs anyway.
if (thorough_tests) dirs_l = cgi_dirs();

if (isnull(dirs_l)) dirs_l = make_list("/");

foreach dir (dirs_l)
{
  len = strlen(dir);
  if (len == 0 || dir[0] != "/")
  {
    dir = "/" + dir;
    len ++;
  }
  if (len > 1 && dir[len-1] != "/") dir = dir + "/";

  foreach ext (exts)
  {
    foreach exploit (exploits)
    {
      if (" " >< exploit) enc_exploit = str_replace(find:" ", replace:"%20", string:exploit);
      else enc_exploit = exploit;

    if (ext)
      urls = make_list(
        dir + enc_exploit + "." + ext,
        dir + file + "." + ext + "?" + enc_exploit
      );
    else
      urls = make_list(
        # nb: does server check "filenames" for Javascript?
        dir + enc_exploit,
        enc_exploit,
        # nb: how about just the request string?
        dir + "?" + enc_exploit
      );

    foreach url (urls)
    {
      if (vuln_url) break;
      # Try to exploit the flaw.
      ef = (failures >= 2);
      r = http_send_recv3(method: 'GET', item:url, port:port, fetch404: TRUE, follow_redirect: 2, exit_on_fail: ef);
      if (isnull(r))
      {
        failures ++;
	continue;
      }

      headers = parse_http_headers(status_line:r[0], headers:r[1]);
      if (!empty_or_null(headers))
      {
        if (!empty_or_null(headers['content-disposition']) &&
            headers['content-disposition'] =~ 'attachment') continue;

        if (!empty_or_null(headers['content-type']))
        {
          if (headers['content-type'] !~ "text\/html")
          {
            rep_extra =
              'Note that this XSS attack may only work against ' +
              'web browsers\nthat have "content sniffing" enabled.';
          } 
        }
      }

      if (exploit >< r[2])
      {
        if (r[0] =~ "^HTTP/1\.[01] 30[12] ") continue;	# FP
        vuln++;

        report += crap(data:"-", length:30)+' Request #' + vuln + ' ' +crap(data:"-", length:30)+ '\n';
        report +=
          '\nThe request string used to detect this flaw was :\n\n' +
          url +
          '\n\nThe output was :\n\n' +
          r[0] + r[1] + '\n' +
          extract_pattern_from_resp(string: r[2], pattern: "ST:"+exploit)+
          '\n';
          if (rep_extra)
            report += rep_extra;

        vuln_url = TRUE;
        hdr_ext = ext;
      }
    }

  }
}

    # begin header tests
    if (thorough_tests)
    {
      foreach hdr (hdrs)
      {
        #build request
        if (empty_or_null(ext)) ext = "html";
        if (empty_or_null(hdr_ext)) hdr_ext = ext;
        exploit = "<script>alert(" + hdr + ")</script>";
        url = dir + file + "." + hdr_ext;
        rq = http_mk_req(item: url, port:port, method: "GET", add_headers: make_array(hdr, exploit));

        #send request
        r = http_send_recv_req(req: rq, port:port, fetch404: TRUE, only_content: "text/(xml|html)");
        if(isnull(r))
        {
          failures ++;
          continue;
        }

        #check response
        if (exploit >< r[2])
        {
          if (r[0] =~ "^HTTP/1\.[01] 30[12] ") continue;  # FP
          vuln++;

          # report
          report += crap(data:"-", length:30)+' Request #' + vuln + ' ' +crap(data:"-", length:30)+ '\n';
          report += '\nThe full request used to detect this flaw was :\n\n' + 
            http_last_sent_request() +
            '\n\nThe output was :\n\n' +
            r[0] + r[1] + '\n' +
            extract_pattern_from_resp(string: r[2], pattern: "ST:"+exploit)+
            '\n';

        }
      }
    }
    # end header tests
}
if (vuln > 0)
{
  set_kb_item(name:string("www/", port, "/generic_xss"), value:TRUE);
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
exit(0, "The web server listening on port " +port+ " is not affected.");
