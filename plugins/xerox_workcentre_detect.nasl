#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18141);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2014/10/30 13:46:39 $");

  script_name(english:"Xerox WorkCentre Device Detection");
  script_summary(english:"Scrapes model and configuration info from web interface.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a printer.");
  script_set_attribute(attribute:"description", value:"The remote host is a Xerox WorkCentre device.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break: 1);

kb_base = "www/xerox_workcentre";
labels["model"] = "Model";
labels["ssw"]   = "System Software Version";
labels["scd"]   = "Software Compatibility Database Version";
labels["ess"]   = "Net Controller Software Version";

# Collect various pieces of data.
data = make_array();
new_ver = FALSE;

res = http_send_recv3(
  method : "GET",
  item   : "/properties/description.dhtml",
  port   : port,
  exit_on_fail : TRUE
);

# - The model number (Properties, Description).
pat = '^[ \t]+(Xerox )?WorkCentre ([^,]+)';
matches = egrep(pattern:pat, string:res[2]);
if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match);
    if (!isnull(item))
    {
      data["model"] = item[2];
      break;
    }
  }
}

if (!max_index(keys(data)))
{
  res = http_send_recv3(
    method : "GET",
    item   : "/properties/configuration.php?tab=Status",
    port   : port,
    exit_on_fail : TRUE
  );

  pat = ">Machine Model:</td><([^\>]+)\>Xerox WorkCentre ([^<]+)\</td\>";
  match = eregmatch(pattern:pat, string:res[2]);
  if (!isnull(match))
  {
    data["model"] = match[2];
    new_ver = TRUE;
  }
}

if (!max_index(keys(data)))
{
  res = http_send_recv3(
    method : "GET",
    item   : "/header.php?tab=status",
    port   : port,
    exit_on_fail : TRUE
  );

  # - The model number.
  pat = '^[ \t]*<div id="productName">XEROX WorkCentre ([^<,]+)</div>';
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        data["model"] = item[1];
        break;
      }
    }
  }
}
if (!max_index(keys(data))) audit(AUDIT_HOST_NOT, "a Xerox WorkCentre device");

# Used to detect newer models such as 5845/5855/5865/5890,
# 7220/7225, 7830/7835, and 7845/7855.  Other versions may apply
# Requesting /properties/configuration.php?tab=Status will provide
# all the info we need without requiring authentication
if (new_ver)
{
  # SSW - System Software Version
  pat1 = "\>System Software Version:\</td\>\<([^\>]+)\>(.+)\</td\>";
  ssw_match = eregmatch(pattern:pat1, string:res[2]);
  if (!isnull(ssw_match))
  {
    data["ssw"] = ssw_match[2];
  }

  # ESS - Net Controller Software Version
  pat2 = ">Network Controller:</td><([^>]+)>(.+)</td>";
  ess_match = eregmatch(pattern:pat2, string:res[2]);
  if (!isnull(ess_match))
  {
    data["ess"] = ess_match[2];
  }
}

else
{
  # nb: the rest of the info comes from a different page.
  res = http_send_recv3(
    method : "GET",
    item   : "/properties/configuration.dhtml",
    port   : port,
    exit_on_fail : TRUE
  );
  if ( (!res[2]) || ("System Software Version:" >!< res[2]) )
  {
    res = http_send_recv3(
      method : "GET",
      item   : "/properties/configurationSpecial.dhtml",
      port   : port,
      exit_on_fail : TRUE
    );
  }
  res = res[2];

  # - System Software version.
  if ("System Software Version:" >< res)
  {
    info = strstr(res, "System Software Version:");
    if ("</tr>" >< info)
    {
      info = info - strstr(info, "</tr>");
      pat = '^[ \t]*([0-9]+[0-9.]+)[ \t]*$';
      foreach line (split(info, keep:FALSE))
      {
        if (match(pattern:pat, string:line))
        {
          data["ssw"] = ereg_replace(pattern:pat, replace:"\1", string:line);
          break;
        }
      }
    }
  }
  if (!data["ssw"])
  {
    pat = "var versions .+, ([^,]+), System Software;";
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          data["ssw"] = item[1];
          break;
        }
      }
    }
  }

  # - Software Compatibility Database.
  pat = "var versions .+, ([^,]+), Software Compatibility Database";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        data["scd"] = item[1];
        break;
      }
    }
  }

  # Examples:
  # 'var SysDescrip = "Xerox WorkCentre Pro Multifunction System,ESS 0.R01.
  # 02.329.01, IOT 23.16.0, UI 0.2.84.14, Finisher 9.15.0, Scanner 15.7.0;";'
  # 'var SysDescrip = "Xerox WorkCentre Pro Multifunction System, ESS 0.S01.02
  # .058.04, IOT 13.0.0, UI 0.1.2.59, Scanner 8.60.0;";'
  # 'var SysDescrip = "Xerox WorkCentre Pro Multifunction System; ESS 0.040.022
  # .51031, IOT 50.17.0, UI 0.12.60.54, Finisher 3.20.0, Scanner 4.9.0,
  # BIOS 07.07";'
  if ('var SysDescrip = "' >< res)
  {
    info = strstr(res, 'var SysDescrip = "') - 'var SysDescrip = "';
    if ('";' >< info)
    {
      info = info - strstr(info, '";');
      if (" ESS " >< info)
      {
        ess = strstr(info, " ESS ") - " ESS ";
        ess = ess - strstr(ess, ", ");
        if (ess =~ "^0\.[RS]") ess = substr(ess, 3);
        else if (ess =~ "^0\.0") ess = substr(ess, 2);

        data["ess"] = ess;
      }
    }
  }

  # If that didn't work...
  if (isnull(ess))
  {
    # It may be two lines after the label 'Engine', as occurs with
    # PE120 Series devices.
    i = 0;
    foreach line (split(res, keep:FALSE))
    {
      if (line =~ "^ +Engine:$")
      {
        data["ess"] = lines[i+2];
        break;
      }
      ++i;
    }
  }
}

# Update KB and report findings.
set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
set_kb_item(name:kb_base, value:TRUE);

max_label_len = 0;
foreach key (keys(data))
{
  label = labels[key];
  if (strlen(label) > max_label_len) max_label_len = strlen(label);
}

info = "";
foreach key (make_list("model", "ssw", "sdc", "ess"))
{
  val = data[key];
  if (!isnull(val))
  {
    set_kb_item(name:kb_base+"/"+key, value:val);

    label = labels[key];
    if (key == "model") val = 'Xerox WorkCentre ' + val;
    info += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
  }
}

if (report_verbosity > 0) security_note(port:port, extra:'\n'+info);
else security_note(port);
