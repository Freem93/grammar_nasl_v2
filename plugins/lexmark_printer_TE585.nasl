#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72772);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id("CVE-2013-6033");
  script_bugtraq_id(65277);
  script_osvdb_id(102752);
  script_xref(name:"CERT", value:"108062");

  script_name(english:"Lexmark Printer Configuration Persistent XSS");
  script_summary(english:"Checks version of Lexmark printer");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote printer is potentially affected by a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the remote Lexmark printer is potentially affected by a
cross-site scripting vulnerability.  An input validation error exists
related to the 'General Settings' configuration page and the 'Location'
and 'Contact Name' parameters that could allow persistent cross-site
scripting attacks."
  );
  # http://support.lexmark.com/index?page=content&id=TE585&locale=EN&userlocale=EN_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b932aa2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the vendor's suggested Lexmark printer firmware version or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c52x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c53x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c920");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:c935dn");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e250");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e350");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:e450");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:t64x");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:lexmark:w840");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("lexmark_printer_detect.nasl");
  script_require_keys("www/lexmark_printer/model", "www/lexmark_printer/base_ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

report_model   = get_kb_item_or_exit("www/lexmark_printer/model");
report_version = get_kb_item_or_exit("www/lexmark_printer/base_ver");

use_model = tolower(report_model - 'Lexmark ');
use_version = tolower(report_version);

if (report_version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "the remote Lexmark printer ("+report_model+")", 0);

# tolower(model regex) , vuln regex
model_and_vuln_vers = make_array(
  "^w840($|[^0-9])",
  # LS.HA.P252 and earlier
  "^ls\.ha\.p(00[0-9]|0[0-9][0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-2]))($|[^0-9])",

  "^t64[0-9]($|[^0-9])",
  # earlier than LS.ST.P344
  "^ls\.st\.p(00[0-9]|0[0-9][0-9]|[12][0-9][0-9]|3([0-3][0-9]|4[0-3]))($|[^0-9])",

  "^c935dn($|[^0-9])",
  # LC.JO.P091 and earlier
  "^lc\.jo\.p(00[0-9]|0[0-8][0-9]|090)($|[^0-9])",

  "^c920($|[^0-9])",
  # LS.TA.P152 and earlier
  "^ls\.ta\.p(00[0-9]|0[0-9][0-9]|1[0-4][0-9]|15[01])($|[^0-9])",

  "^c53[0-9]($|[^0-9])",
  # LS.SW.P069 and earlier
  "^ls\.sw\.p(00[0-9]|0[0-6][0-9])($|[^0-9])",

  "^c52[0-9]($|[^0-9])",
  # LS.FA.P150 and earlier
  "^ls\.fa\.p(00[0-9]|0[0-9][0-9]|1[0-4][0-9]|150)($|[^0-9])",

  "^e450($|[^0-9])",
  # LM.SZ.P124 and earlier
  "^lm\.sz\.p(00[0-9]|0[0-9][0-9]|1[01][0-9]|12[0-4])($|[^0-9])",

  "^e350($|[^0-9])",
  # LE.PH.P129 and earlier
  "^le\.ph\.p(00[0-9]|0[0-9][0-9]|1[0-2][0-9])($|[^0-9])",

  "^e250($|[^0-9])",
  # LE.PM.P126 and earlier
  "^le\.pm\.p(00[0-9]|0[0-9][0-9]|1[01][0-9]|12[0-6])($|[^0-9])"
);

# tolower(model regex) , fix
model_and_fix_vers = make_array(
  "^w840($|[^0-9])"    , "Contact vendor",
  "^t64[0-9]($|[^0-9])", "LS.ST.P344",
  "^c935dn($|[^0-9])"  , "Contact vendor",
  "^c920($|[^0-9])"    , "Contact vendor",
  "^c53[0-9]($|[^0-9])", "Contact vendor",
  "^c52[0-9]($|[^0-9])", "Contact vendor",
  "^e450($|[^0-9])"    , "Contact vendor",
  "^e350($|[^0-9])"    , "Contact vendor",
  "^e250($|[^0-9])"    , "Contact vendor"
);

vuln_regex = NULL;
report_fix = FALSE;

# See if detected model is in the affected list
foreach model_regex (keys(model_and_vuln_vers))
{
  if (use_model =~ model_regex)
  {
    vuln_regex = model_and_vuln_vers[model_regex];

    # Do the vercheck
    if (use_version =~ vuln_regex)
    {
      vuln = TRUE;
      report_fix = model_and_fix_vers[model_regex];
    }
    break;
  }
}

if (report_fix)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  Model             : ' + report_model +
             '\n  Installed version : ' + report_version +
             '\n  Fixed version     : ' + report_fix +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "The Lexmark printer ("+report_model+")", report_version);
