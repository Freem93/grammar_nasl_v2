#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50577);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/03/14 21:48:12 $");

  script_name(english:"Ricoh Printer Detection");
  script_summary(english:"Scrapes model and configuration info from web interface.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a printer.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Ricoh Printer.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break:1);
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("Web-Server/" >!< banner) exit(0, "The web server on port "+port+" does not look like it's a Ricoh printer.");

kb_base = "www/ricoh";
labels['model'] = "Model";
labels['mid'] = "Machine ID";
labels['sysver'] = "System Version";
labels['nibver'] = "NIB Version";
labels['wimver'] = "Web Image Monitor Version";

# Collect various pieces of data
data = make_array();
res = http_send_recv3(method:"GET", item:"/web/user/en/websys/status/system.cgi", port:port, exit_on_fail:TRUE);
# - Model Number
if ("Model Name" >< res[2])
{
  info = strstr(res[2], "Model Name");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[\\s]*<td nowrap="nowrap">(Aficio [0-9A-Za-z]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['model'] = item[1];
      }
    }
  }
}
if (!max_index(keys(data))) exit(0, "The remote host does not appear to be a Ricoh printer.");

# - Machine ID
if ("Machine ID" >< res[2])
{
  info = strstr(res[2], "Machine ID");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap="nowrap">([A-Z0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['mid'] = item[1];
      }
    }
  }
}

# - System Version
if ("System" >< res[2])
{
  info = strstr(res[2], "System");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap="nowrap">([0-9]+\\.[0-9]+\\.[0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['sysver'] = item[1];
      }
    }
  }
}

# - NIB Version
if ("NIB" >< res[2])
{
  info = strstr(res[2], "NIB");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap="nowrap">([0-9]+\\.[0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['nibver'] = item[1];
      }
    }
  }
}

# - Web Image Monitor Version
if ("Web Image Monitor" >< res[2])
{
  info = strstr(res[2], "Web Image Monitor");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap="nowrap">([0-9]+\\.[0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['wimver'] = item[1];
      }
    }
  }
}

# Update KB and report finding.
set_kb_item(name:'Services/www'+port+'/embedded', value:TRUE);
set_kb_item(name:kb_base, value:TRUE);

max_label_len = 0;
foreach key (keys(data))
{
  label = labels[key];
  if (strlen(label) > max_label_len) max_label_len = strlen(label);
}

info = "";
foreach key (make_list('model', 'mid', 'sysver', 'nibver', 'wimver'))
{
  if (val = data[key])
  {
    set_kb_item(name:kb_base+'/'+key, value:val);

    label = labels[key];
    if (key == "model") val = 'Ricoh ' + val;
    info += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
  }
}

if (report_verbosity > 0)
{
  report = '\n' + info;
  security_note(port:port, extra:report);
}
else security_note(port);
