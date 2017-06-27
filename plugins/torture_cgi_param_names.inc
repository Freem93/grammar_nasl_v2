# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# torture_cgi_param_names.inc
# $Revision: 1.3 $
# $Date: 2014/10/07 23:53:22 $
#

include("torture_cgi_headers.inc");

global_var	flaws_and_patterns;


function test(meth, url, postdata, cgi, vul)
{
  local_var	r, i, p, rq, txt, ct, idx, url1, url2, postdata0;

  if (vul[0] == "X" && report_paranoia < 2)
    ct = "text/(xml|html)";
  else
    ct = NULL;

  url = my_encode(url);
  postdata0 = postdata;

  idx = stridx(url, '?');
  if (idx > 0)
  {
    url1 = substr(url, 0, idx - 1);
    url2 = substr(url, idx+1);
  }
  else if (idx == 0)	# Degenerate case: broken URL
  {
    url1 = '';
    url2 = substr(url, 1);
  }
  else	# idx < 0
  {
    url1 = url;
    url2 = '';
  }
  url1 += '?';
  if (strlen(url2) > 0) url2 = '&' + url2;

  if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
    return -1;

  foreach p (keys(flaws_and_patterns))
  {
    if (isnull(postdata))
    {
      url = strcat(url1, p, '=1', url2);
      debug_print(level:2, 'URL=', url, '\n');
      rq = http_mk_req(item: url, port:port, method: meth);
    }
    else
    {
      postdata = strcat(p, '=1&', postdata0);
      rq = http_mk_req(item: url, port:port, method: meth, data:postdata);
    }
    r = http_send_recv_req(req: rq, port:port, only_content: ct, exit_on_fail: 0);
    if (isnull(r))
    {
      if ('\n' >< p)	# This badly breaks the HTTP protocol
        continue;
      else
	return 0;
    }

    # Ignore Tomcat /appdev/processes*.html and /docs/.*.html files
    if (ereg(
      pattern : "(/appdev/.*\.html|/docs/.*\.html)",
      string  : url,
      multiline :TRUE)
    )
    {
      if (ereg(
        pattern : "Tomcat",
        string  : r[2],
        icase   : TRUE,
        multiline : TRUE)
      ) continue;
    }

    # torture_cgi_audit_response cannot be called here (no poisoned parameter)

    txt = sanitize_utf16(body: r[2], headers: r[1]);
    if (vul[0] == "X")
      txt = extract_pattern_from_resp(pattern: flaws_and_patterns[p], string: txt);
    else	# SQL injection test
      txt = extract_pattern_from_resp(pattern: flaws_and_patterns[p], 
      	  response: mk_list_silent3(r[0], r[1], txt));
    if (txt)
    {
      torture_cgi_remember(port: port, url: url, request: http_mk_buffer_from_req(req: rq),
        response: r, cgi: cgi, vul: vul, method: meth, report: txt);
      return 1;
    }
  }
  return -1;
}

function run_injection_param_names(vul, ext_l)
{
  return run_injection_hdr(vul: vul, ext_l: ext_l);
}
