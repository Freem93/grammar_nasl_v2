#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49806);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/07/11 22:13:38 $");

  script_cve_id("CVE-2010-3332");
  script_bugtraq_id(43316);
  script_osvdb_id(68127);
  script_xref(name:"MSFT", value:"MS10-070");

  script_name(english:"MS10-070: Vulnerability in ASP.NET Could Allow Information Disclosure (2418042) (uncredentialed check)");
  script_summary(english:"Test vulnerability of ASP.NET to MS10-070");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET framework installed on the remote host has an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There is an information disclosure vulnerability in ASP.NET, part of
the .NET framework.  Information can be leaked due to improper error
handling during encryption padding.

A remote attacker could exploit this to decrypt and modify an ASP.NET
application's server-encrypted data.  In .NET Framework 3.5 SP1 and
above, an attacker could exploit this to download any file within the
ASP.NET application, including web.config."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-070");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencie("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function base64url_decode(str)
{
  local_var cstr,padlen;

  # strip last char
  cstr = substr(str, 0, strlen(str) - 2);

  # num of '=' to pad
  padlen = str[strlen(str) -1];

  cstr = str_replace(string:cstr, find:"-",replace:"+");
  cstr = str_replace(string:cstr, find:"_",replace:"/");
  cstr += crap(data:"=",length:padlen);

  return base64_decode(str:cstr);
}

function base64url_encode(str)
{
  local_var cstr, idx, padchars;

  cstr = base64(str:str);

  # look for '='
  idx = stridx(cstr,"=");

  if(idx != -1)
  {
    padchars  = substr(cstr, idx, strlen(cstr) -1);

    cstr      = substr(cstr, 0, idx -1);
    cstr      += strlen(padchars);
  }
  else # no padding
    cstr += "0";

  cstr = str_replace(string:cstr, find:"+",replace:"-");
  cstr = str_replace(string:cstr, find:"/",replace:"_");

  return cstr;
}

#
# parse link like url?arg1=value1&arg2=value2...
#
# ret['url']    = url part
# ret['args']   = array of 'arg' associative arrays
#
function parse_link(link)
{
  local_var ret, arg_pair_l, arg_pair, array, arg, match;

  match = eregmatch(string:link,pattern:"^(.+)\?(.+)$");

  # link with no arguments
  if(! match)
  {
    ret['url'] = link;
    return ret;
  }

  ret['url'] = match[1];
  arg_pair_l = split(match[2],sep:"&", keep:FALSE);

  foreach arg_pair(arg_pair_l)
  {
    array = split(arg_pair,sep:"=",keep:FALSE);
    arg[array[0]]  = array[1];
  }

  ret['args'] = arg;

  return ret;
}

# Perform the axd check with the given d and t arguments
function check_axd_go(port, path, d, t)
{
  local_var req, res, axd, fixed, original, final_url, links, array, item;

  # Make sure we have all the arguments we need
  if(isnull(path) || isnull(d) || isnull(t))
    return NULL;

  #decode
  original = base64url_decode(str:d);

  #change the last byte
  fixed = original;
  fixed[strlen(fixed)-1] = raw_string(ord(fixed[strlen(fixed) - 1]) -1);

  #re-encode
  fixed = base64url_encode(str:fixed);

  #build the final url to request
  final_url = "/" + path + '?d=' + fixed + '&t=' + t;

  #Resend the request with the changed padding
  req = http_mk_get_req(port:port, item: final_url, version: 11);
  res = http_send_recv_req(port:port, req:req, fetch404:TRUE, exit_on_fail:TRUE);

  # See if the page contained a padding error
  if("adding is invalid" >< res[2])
  {
    return path + " returned a padding error.";
  }
  else if(("CryptographicException" >< res[2]) || ("Bad Data" >< res[2]))
  {
    return path + " returned a runtime error.";
  }
  else if("404" >< res[0])
  {
    exit(0, "The web server on port " + port + " returned a 404 error on " + path + " with invalid padding.");
  }
  else if("302" >< res[0])
  {
    exit(0, "The web server on port " + port + " returned a HTTP Redirect on " + path + " with invalid padding, which may indicate mitigation is in place.");
  }
  else
  {
    return NULL;
  }
}

function check_axd(port, path)
{
  local_var req, res, axd, fixed, original, final_url, links, array, item;
  local_var link, result;
  local_var args;
  req = http_mk_get_req(port:port, item:path, version: 11);
  res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE, fetch404:TRUE);

  links = egrep(pattern:'\\.axd', string:res[2]);

  if(!links)
    return NULL;

  array = split(links, sep:'\n');

  foreach item(array)
  {
    item = chomp(item);

    axd = eregmatch(pattern:'[\'"]([^"\']+\\.axd[^\'"]*)["\']', string:item);

    if(!isnull(axd))
    {
      if("http" >!< axd[0])
      {
        link = parse_link(link:axd[1]);
 	args = link['args'];
        result = check_axd_go(port:port, path:link['url'], d:args['d'], t:args['t']);

        if(!isnull(result))
        {
          return result;
        }
      }
    }
  }
}

function check_viewstate_go(port, path, viewstate, event_validation)
{
  local_var viewstate_bin, fixed, postdata, res;

  # make sure we have all the arguments we need
  if(isnull(path) || isnull(viewstate) || isnull(event_validation))
    return NULL;

  # Decode
  viewstate_bin = base64_decode(str: viewstate);

  # Modify the last character in the string to induce a padding error
  fixed = viewstate_bin;
  fixed[strlen(fixed)-1] = raw_string(ord(fixed[strlen(fixed) - 1]) -1);

  # Re-encode
  fixed = base64(str:fixed);

  # URL-encode the strings (we only have to worry about three symbols)
  fixed = str_replace(string:fixed, find:"+",replace:"%2b");
  fixed = str_replace(string:fixed, find:"/",replace:"%2f");
  fixed = str_replace(string:fixed, find:"=",replace:"%3d");
  event_validation = str_replace(string:event_validation, find:"+",replace:"%2b");
  event_validation = str_replace(string:event_validation, find:"/",replace:"%2f");
  event_validation = str_replace(string:event_validation, find:"=",replace:"%3d");

  postdata = "__VIEWSTATE=" + fixed + "&" + "__EVENTVALIDATION=" + event_validation + "&__VIEWSTATEENCRYPTED=''";

  res = http_send_recv3(method: "POST", item: "/", port: port, content_type: "application/x-www-form-urlencoded", data: postdata, exit_on_fail:TRUE, fetch404:TRUE);

  if("adding is invalid" >< res[2])
  {
    return "Viewstate at " + path + " returned a padding error.";
  }
  else if("rypto" >< res[2] && 'xception' >< res[2])
  {
    return "Viewstate at " + path + " returned a cryptographic exception.";
  }
  else
  {
    return NULL;
  }

}

function mk_list()
{
  if (isnull(_FCT_ANON_ARGS[0]))	return make_list();
  else					return make_list(_FCT_ANON_ARGS[0]);
}

function check_viewstate(port, path)
{
  local_var req, res, viewstate, event_validation;

  req = http_mk_get_req(port:port, item:path, version: 11);
  res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE, fetch404:TRUE);

  if("__VIEWSTATE" >!< res[2])
  {
    return NULL;
  }

  if("__VIEWSTATEENCRYPTED" >!< res[2])
  {
    return NULL;
  }

  viewstate = eregmatch(pattern:'<[^>]+hidden[^>]+name=["\']__VIEWSTATE[^>]+value=["\']([^"\']+)["\']', string:res[2]);
  event_validation = eregmatch(pattern:'<[^>]+hidden[^>]+name=["\']__EVENTVALIDATION[^>]+value=["\']([^"\']+)["\']', string:res[2]);

  if(isnull(viewstate) || isnull(event_validation))
  {
    return NULL;
  }

  return check_viewstate_go(port:port, path:path, viewstate:viewstate[1], event_validation:event_validation[1]);
}

local_var port, axd_files, viewstate_files;
local_var axd_count, viewstate_count;


port = get_http_port(default:80);

# Get a list of .axd files from the webspider script. If CGI scanning is off,
# this will be less effective.
axd_files = get_kb_list("www/" + port + "/content/extensions/axd");

if(isnull(axd_files))
{
  local_var result;
  # If we don't have the webmirror extension, check the root folder
  result = check_axd(port:port, path:'/');

  if(!isnull(result))
  {
    security_warning(port:port, extra:'\n' + result + '\n');
    exit(0);
  }
}
else
{
  axd_files = make_list(axd_files);
  axd_count = 0;

  foreach axd(axd_files)
  {
    local_var d_list, t_list;
    d_list = get_kb_list("www/" + port + "/cgi-params" + axd + "/d");
    t_list = get_kb_list("www/" + port + "/cgi-params" + axd + "/t");

    if(!isnull(d_list) && !isnull(t_list))
    {
      local_var max, i;

      d_list = make_list(d_list);
      t_list = make_list(t_list);

      max = max_index(d_list);

      for(i = 0; i < max; i++)
      {
        local_var d, t;
        d = d_list[i];
        t = t_list[i];
        if(isnull(t))
          t = '';

        result = check_axd_go(port:port, path:axd, d:d, t:t);
        if(!isnull(result))
        {
          security_warning(port:port, extra:'\n' + result + '\n');
          exit(0);
        }
      }

      # Limit the number of files we check
      if(axd_count > 4)
        break;
      axd_count++;
    }
  }
}

# Get a list of all .cgis. If CGI scanning is turned off, again, this will be more complicated
viewstate_files = get_kb_list('www/' + port + '/cgi');
if(isnull(viewstate_files))
{
  # Check the root path only
  local_var result;
  result = check_viewstate(port:port, path:'/');
  if(!isnull(result))
  {
    security_warning(port:port, extra:'\n' + result + '\n');
    exit(0);
  }
}
else
{
  viewstate_files = make_list(viewstate_files);
  viewstate_count = 0;

  # Search our viewstate files for one with __VIEWSTATEENCRYPTED
  foreach file(viewstate_files)
  {
    local_var viewstateencrypted;

    viewstate_encrypted = get_kb_list("www/" + port + "/cgi-params" + file + "/__VIEWSTATEENCRYPTED");

    if(!isnull(viewstate_encrypted))
    {
      local_var viewstate, event_validation, result;

      lVS = mk_list(get_kb_list("www/" + port + "/cgi-params" + file + "/__VIEWSTATE"));
      foreach viewstate (lVS)
      {
        lEV = mk_list(get_kb_list("www/" + port + "/cgi-params" + file + "/__EVENTVALIDATION"));
	foreach event_validation (lEV)
	{
	  result = check_viewstate_go(port:port, path:file, viewstate:viewstate, event_validation:event_validation);

	  if(!isnull(result))
	  {
	    security_warning(port:port, extra:'\n' + result + '\n');
	    exit(0);
	  }
        }
      }
    }

    # Limit the number of files we check
    if(viewstate_count > 4)
      break;
    viewstate_count++;
  }

}

exit(0, "The web server on port " + port + " didn't have a vulnerable .axd file or encrypted viewstate that could be found.");

