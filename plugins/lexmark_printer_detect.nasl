#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46311);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/22 21:12:16 $");

  script_name(english:"Lexmark Printer Detection");
  script_summary(english:"Scrapes model and other version info from web interface");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a printer.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Lexmark printer.

By querying the device information page, this plugin attempts to
identify the model, and various other key software versions such as
kernel, engine, base installed on the remote Lexmark device.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Scan/Do_Scan_Printers");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break: 1);

res = http_get_cache(port:port, item:"/",exit_on_fail: TRUE);

# Poor-man's decode since this is the only one seen so far
res = str_replace(string:res, find:"&#032;", replace:" ");

data = make_array();

pat = '<TITLE>Lexmark ([A-Za-z0-9]+)</TITLE>';
if(egrep(pattern:pat,string:res, icase:TRUE) )
{
  matches = eregmatch(pattern:pat,string:res, icase:TRUE);
  foreach match (split(matches, keep:FALSE))
  {
    item = eregmatch(pattern:pat, string:match, icase:TRUE);
    if (!isnull(item))
    {
      data["model"] = item[1];
      break;
    }
  }
}

if (!max_index(keys(data))) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "the Lexmark printer", port);

kb_base = "www/lexmark_printer";

labels["model"]            = "Model";
labels["base_ver"]         = "Base Version";
labels["loader_ver"]       = "Loader Version";
labels["kernel_ver"]       = "Kernel Version";
labels["engine_ver"]       = "Engine Version";
labels["network_ver"]      = "Network Version";
labels["network_drv_ver"]  = "Network Driver Version";
labels["basic_kernel_ver"] = "Basic Kernel Version";

# Get information about the device.

url_list = make_list(
             "/printer/info",
             "/cgi-bin/dynamic/config/reports/deviceinfo.html",
             "/cgi-bin/dynamic/information.html?path=/printer/info",
             "/cgi-bin/dynamic/printer/config/reports/deviceinfo.html");

info = "";

foreach url (url_list)
{
  res = http_send_recv3(method: "GET", item:url, port:port,exit_on_fail:TRUE);

  if (">Printer Revision Levels:<" >< res[1] || ">Printer Revision Levels:<" >< res[2])
  {
    # Version info is either in res[1] or res[2]
    if(">Printer Revision Levels:<" >< res[1])
      res = res[1];
    else
      res = res[2];

    pat = ">([A-Za-z0-9_]+[. ][0-9A-Za-z_-]+[.]*([A-Za-z0-9_-]+)?)</";
    ver_txt = "";

    foreach line (split(res))
    {
      # Set a flag if we find one of the elements
      # we are looking for, and then extract the
      # version from the next line.
     if(">Basic Kernel</" >< line)
         ver_txt = "basic_kernel_ver";
     else if (">Kernel</" >< line)
         ver_txt =  "kernel_ver";
     else if (">Base</" >< line)
         ver_txt =  "base_ver";
      else if (">Network Drvr</" >< line)
         ver_txt =  "network_drv_ver";
      else if (">Engine</" >< line)
         ver_txt =  "engine_ver";
      else if ( ">Network</" >< line)
         ver_txt =  "network_ver";
      else if(ver_txt && ereg(pattern:pat,string:line))
      {
        matches = eregmatch(pattern:pat,string:line);
        if(matches && matches[1])
        {
          data[ver_txt] = matches[1];
          info +=  data[ver_txt];
          ver_txt = "";
        }
      }
    }
  }

  else if(">Device Information<" >< res[2])
  {
    start_pat = "<TR><TD>.+>";
    end_pat   = "</P></TD><TD><P> *= *([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+) *</P><";

    ver_txt = make_array();

    ver_txt["Engine"]        = "engine_ver";
    ver_txt["Loader"]        = "loader_ver";
    ver_txt["Base"]          = "base_ver";
    ver_txt["Network"]       = "network_ver";
    ver_txt["Network Drvr"]  = "network_drv_ver";

    foreach line (split(res[2]))
    {
      foreach element (make_list("Engine","Loader","Base","Network", "Network Drvr"))
      {
        if(ereg(pattern:start_pat + element + end_pat, string:line, icase:TRUE))
        {
          matches = eregmatch(pattern:start_pat + element + end_pat,string:line, icase:TRUE);
          if(matches && matches[1])
          {
            data[ver_txt[element]] = matches[1];
            info += data[ver_txt[element]];
            break;
          }
        }
      }
    }
  }
  if (info) break;
}

if(!info)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "the Lexmark printer", port);

# Extract the max_label_len, to make the final report
# cleaner.

max_label_len = 0;
foreach key (keys(data))
{
  label = labels[key];
  if (strlen(label) > max_label_len) max_label_len = strlen(label);
}

info2 = "";
foreach key (make_list("model", "base_ver", "engine_ver", "loader_ver", "network_ver", "network_drv_ver","kernel_ver" ,"basic_kernel_ver"))
{
  if (!isnull(data[key]))
  {
    val = data[key];
    set_kb_item(name:kb_base+"/"+key, value:val);

    label = labels[key];
    if (key == "model") val = 'Lexmark ' + val;
    info2 += '  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + val + '\n';
  }
}

if (info2)
{
  if(report_verbosity > 0)
  {
    report = '\n' +
      info2;
    security_note(port:port, extra:report);
  }
  else security_note(port);

  exit(0);
}
else
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "the Lexmark printer", port);
