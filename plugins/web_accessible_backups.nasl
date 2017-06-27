#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72771);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"Web Accessible Backups");
  script_summary(english:"Looks for backup archives");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts web-accessible backups or archives.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting web-accessible archive files that may
contain backups or sensitive data.");
  script_set_attribute(attribute:"solution", value:
"Review each of the files and ensure they are in compliance with your
security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

# Common archive extensions
exts = make_list(".tar", ".tar.gz", ".gz", ".tgz", ".tar.bz2", ".bz2", ".zip", ".jar", ".war", ".rar", ".7z", ".Z", ".z");

tld_host = get_host_name();
tld_host2 = NULL;
domain = NULL;
domain2 = NULL;

if (tld_host !~ "^(\d{1,3}\.){3}\d{1,3}$")
{
  fqdn = split(tld_host, sep:".", keep:TRUE);

  if (max_index(fqdn) >= 2)
  {
    domain = '';
    for (i=0; i < max_index(fqdn) -1; i++)
    {
      # Handle cases where we have 2 letter CCTLD's ie: test.co.uk
      # and replace without the CCTLD ie: test.
      fqdn[i] = ereg_replace(
        pattern : "^([a-zA-Z]{2}\.)",
        string  : fqdn[i],
        replace : ""
      );
      domain += fqdn[i];
    }
  }

  # Check for cases such as test.com.mx of test.edu.cn and rewrite as test.
  r = ereg(
    pattern : "(\.(com|net|gov|edu|mil|org|web|k12))?\.([a-zA-Z]{2})$",
    string  : tld_host
  );

  if (r)
  {
    domain = ereg_replace(
      pattern : "\.(com|net|gov|edu|mil|org|web|k12)?\.$",
      string  : domain,
      replace : ""
    );
  }
  # Remove the trailing . in the domain name
  domain = ereg_replace(pattern:"\.$", string:domain, replace:"");

  # Remove www. subdomain if present
  www_pat = "^www\.";
  if (domain =~ www_pat)
  {
    domain2 = ereg_replace(pattern:www_pat, string:domain, replace:"");
  }
  if (tld_host =~ www_pat)
  {
    tld_host2 = ereg_replace(pattern:www_pat, string:tld_host, replace:"");
  }
  # Add the www. subdomain if not present
  if (domain !~ www_pat)
  {
    domain2 = "www." + domain;
  }
  if (tld_host !~ www_pat)
  {
    tld_host2 = "www." + tld_host;
  }

}
# If we just have an IP and no FQDN, add the www. subdomain to our checks
else tld_host2 = "www." + tld_host;

files = make_list();
# Add extension to FQDN to test with (ie: tenable.com.zip)
# Add extension to target without FQDN if applicable (ie: tenable.zip)
# Add the www. subdomain to our FQDN / Remove it if supplied by user
foreach ext (exts)
{
  files = make_list("/" + tld_host + ext, files);
  if (!isnull(tld_host2))
  {
    files = make_list("/" +tld_host2 + ext, files);
  }
  if (!isnull(domain))
    files = make_list("/" + domain + ext, files);
  if (!isnull(domain2))
    files = make_list("/" + domain2 + ext, files);
}

# NB: http://www.garykessler.net/library/file_sigs.html
# NB: http://en.wikipedia.org/wiki/List_of_file_signatures
# NB: http://www.astro.keele.ac.uk/oldusers/rno/Computing/File_magic.html
magic_bytes = make_array();
# 1. .tar, .tar.gz, .tgz, .gz  2. TAR (POSIX)  3. 7-zip TAR
magic_bytes["TAR"] = "^1f8b08|7573746172|3130303737372000";
magic_bytes["Compress"] = "^1f(a0|9d)";       # .z, .tar.z
magic_bytes["BZIP2"] = "^425a68";             # .tar.bz2, .bz2, .tbz2, .tb2
magic_bytes["ZIP"] = "^504b0[357]";           # .zip, .jar, .war
magic_bytes["RAR"] = "^526172211a070(0|1)";   # .rar
magic_bytes["7Z"] = "^377abcaf271c";          # 7-Zip compressed file

if (thorough_tests)
{
  dirs = get_kb_list("www/" +port+ "/content/directories");
  if (isnull(dirs))
    dirs = list_uniq(make_list("/backup", "/backups", "/install", cgi_dirs()));
  else
    dirs = list_uniq(make_list(cgi_dirs(), dirs));
}
else
  dirs = make_list(cgi_dirs());

vuln = make_array();
foreach dir (dirs)
{
  foreach file (files)
  {
    url = dir + file;
    res = http_send_recv3(
      method : "GET",
      item   : url,
      port   : port,
      exit_on_fail : TRUE
    );

    if (res[0] =~ "200 OK")
    {
      # Check for responses with Content-Location which specifies the location
      # or a resource that is separate from the requested URI. RFC2616-sec14
      # Add the resource to our files list if it's not already there
      if (res[1] =~ "Content-Location")
      {
        item = eregmatch(pattern:"Content-Location: (.+)", string:res[1]);
        if (!isnull(item))
        {
          match = chomp(item[1]);
          if (match !~ "^/") match = "/" + match;

          found = FALSE;
          f_list = make_list();
          f_list = make_list(f_list, files);
          foreach f (f_list)
          {
            if (match == f)
            {
              found = TRUE;
              break;
            }
          }
          if (!found)
          {
            files = make_list(files, match);
            continue;
          }
          else continue;
        }
        else continue;
      }
      foreach mb (keys(magic_bytes))
      {
        if (ereg(pattern:magic_bytes[mb], string:hexstr(res[2]), icase:TRUE))
        {
          vuln[mb] += join(build_url(qs:url, port:port) + ",");
        }
      }
    }
  }
}

# Verify any archives we find in our KB (thorough_tests only)
if (thorough_tests)
{
  files = make_list();
  foreach ext (exts)
  {
    kb_ext = ereg_replace(string:ext, pattern:"\.", replace:"");
    f = get_kb_list("www/" +port+ "/content/extensions/" + kb_ext);
    if (!isnull(f))
      files = make_list(f, files);
  }

  if (max_index(files) != 0)
  {
    foreach file (files)
    {
      res = http_send_recv3(
        method : "GET",
        item   : file,
        port   : port,
        exit_on_fail : TRUE
      );

      if (res[0] =~ "200 OK")
      {
        foreach mb (keys(magic_bytes))
        {
          if (ereg(pattern:magic_bytes[mb], string:hexstr(res[2]), icase:TRUE))
          {
            vuln[mb] += join(build_url(qs:file, port:port) + ",");
          }
        }
      }
    }
  }
}

index = max_index(keys(vuln));
if (index == 0) audit(AUDIT_WEB_FILES_NOT, "archive", port);

if (report_verbosity > 0)
{
  if (index == 1)
    file = " file ";
  else
    file = " files ";
  report = '\nNessus was able to identify the following archive'+file+'on the' +
  '\nremote web server :\n';

  foreach arch (sort(keys(vuln)))
  {
    report += '\n' + arch + ' Archive :\n';
    url_split = split(vuln[arch], sep:",", keep:FALSE);
    vuln_lists = make_list();

    # Ensure our report does not contain duplicate entries
    foreach vuln_url (url_split)
    {
      vuln_lists = list_uniq(make_list(vuln_url, vuln_lists));
    }
    foreach item (vuln_lists)
    {
      report += "   " + item + '\n';
    }
  }
  security_note(port:port, extra:report);
}
else security_note(port);
