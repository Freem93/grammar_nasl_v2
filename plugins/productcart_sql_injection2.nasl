#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18436);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-1967", "CVE-2005-2445");
  script_bugtraq_id(13881);
  script_osvdb_id(17329, 17330, 17331, 17332);

  script_name(english:"ProductCart Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple SQL injection issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ProductCart shopping cart
software that fails to properly sanitize user-supplied input before
using it in SQL queries.  An attacker may be able to exploit these
flaws to alter database queries, disclose sensitive information, or
conduct other such attacks.  Possible attack vectors include the
'idcategory' parameter of the 'viewPrd.asp' script, the 'lid'
parameter of the 'editCategories.asp' script, the 'idc' parameter of
the 'modCustomCardPaymentOpt.asp' script, and the 'idccr' parameter of
the 'OptionFieldsEdit.asp' script." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/519" );
  # http://web.archive.org/web/20091106052807/http://echo.or.id/adv/adv16-theday-2005.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed6e090e" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/16");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:early_impact:product_cart");
script_end_attributes();


  summary["english"] = "Checks for multiple SQL injection vulnerabilities (2) in ProductCart";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Check various directories for ProductCart.
foreach dir (cgi_dirs()) {
  # nb: the exploit requires a valid product id.

  # Try to pull up ProductCart's list of categories.
  r = http_send_recv3(method:"GET", item:string(dir, "/viewCat.asp"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like ProductCart...
  if (res =~ "<a href=viewCat.asp>.+Our Products</a>") {
    # Get category ids.
    ncats = 0;
    pat = "href='viewCat_h.asp?idCategory=([0-9]+)'>";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        cat = eregmatch(pattern:pat, string:match);
        if (!isnull(cat)) cats[ncats++] = cat[1];
      }
    }

    # Get product ids for a given category.
    for (i=0; i< ncats; i++) {
      cat = cats[i];

      r = http_send_recv3(method:"GET", item:string(dir, "/viewCat_h.asp?idCategory=", cat), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      pat = string("href='viewPrd.asp?idcategory=", cat, "&idproduct=([0-9]+)'>");
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          prod = eregmatch(pattern:pat, string:match);
          if (!isnull(prod)) {
            prod = prod[1];
            # nb: we only need to find 1 valid product id.      
            break;
          }
        }
      }

      # If we have a product id, try to exploit the flaw.
      if (prod) {
        r = http_send_recv3(method:"GET",
          item:string(
            dir, "/viewPrd.asp?",
            "idcategory=", cat, "'&",
            "idproduct=", prod
          ), 
          port:port
        );
        if (isnull(r)) exit(0);
	res = r[2];

        # There's a problem if we see a syntax error.
        if (egrep(string:res, pattern:string("Syntax error.+'idcategory=", cat), icase:TRUE)) {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }

        # We're not vulnerable, but we're finished checking this dir.
        break;
      }
    }
  }
}
