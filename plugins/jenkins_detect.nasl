#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65054);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/08 19:52:05 $");

  script_name(english:"Jenkins Detection");
  script_summary(english:"Detects Jenkins.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling / management system.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Jenkins, a job scheduling / management
system and a drop-in replacement for Hudson.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/index.html");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/jenkins/about");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Jenkins";
port = get_http_port(default:8080, embedded:FALSE);
version = NULL;
edition = NULL;
hudson_version = UNKNOWN_VER;

# sanity check root for X-Jenkins header
res = http_send_recv3(item:"/", port:port, method:"GET", exit_on_fail:TRUE);
if ("X-Jenkins:" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# attempt modern detection
res = http_send_recv3(
  item:"/login",
  port:port,
  method:"GET",
  exit_on_fail:TRUE
);
if ("X-Jenkins:" >< res[1] && '<span class="jenkins_ver">' >< res[2])
{
  # modern detection

  # grab version from header
  item = eregmatch(pattern:"X-Jenkins: ([0-9.]+)", string: res[1]);
  if (!empty_or_null(item)) version = item[1];

  # grab hudson version from header
  item = eregmatch(pattern:"X-Hudson: ([0-9.]+)", string: res[1]);
  if (!empty_or_null(item)) hudson_version = item[1];

  # figure out what edition this is
  if ("CloudBees Jenkins Operations Center" >< res[2] || "CloudBees+Jenkins+Operations+Center" >< res[2])
    edition = "Operations Center";
  else if ("CloudBees Jenkins Enterprise" >< res[2] || "CloudBees+Jenkins+Enterprise" >< res[2])
    edition = "Enterprise";
  else if ("Jenkins ver. " >< res[2])
    edition = "Open Source"; # might be LTS, checks that later

  if (!empty_or_null(version) && !empty_or_null(edition))
  {
    # modern detection succeeded
    # still need to set some KBs for legacy plugins

    if (edition != "Operations Center")
    {
      # legacy plugins don't know about ops center so will FP these
      # thinking they are Open Source if we include them
      # legacy KBs
      set_kb_item(name:'www/Jenkins', value:TRUE);
      set_kb_item(name:"www/Jenkins/"+port+"/Installed", value:TRUE);
      set_kb_item(name:"www/Jenkins/" + port + "/JenkinsVersion", value:version);
      set_kb_item(name:"www/Jenkins/" + port + "/HudsonVersion", value:hudson_version);
    }

    if (edition == "Enterprise")
    {
      # legacy KBs
      set_kb_item(name:"www/Jenkins/"+port+"/enterprise/Installed", value:TRUE);
      set_kb_item(name:"www/Jenkins/"+port+"/enterprise/CloudBeesVersion", value:version);
    }

    if (edition == "Open Source")
    {
      # legacy KBs
      # All LTS releases are max_index == 3
      # All non-LTS releases are max_index == 2, EXCEPT one non-LTS
      # release : 1.395.1, so do not mark that one as LTS
      if (
        (max_index(split(version, sep:".", keep:FALSE)) == 3) &&
        version != '1.395.1'
      )
      {
        set_kb_item(name:"www/Jenkins/" + port + "/is_LTS", value:TRUE);
        # if it's LTS, we set it to LTS
        edition = "Open Source LTS";
      }
    }

    # register the install and exit
    register_install(
      app_name : appname,
      path     : '/',
      version  : version,
      port     : port,
      cpe      : "cpe:/a:cloudbees:jenkins",
      webapp   : TRUE,
      extra    : make_array("Edition", edition, "Hudson Version", hudson_version)
    );
    report_installs(port:port, app_name:appname);
    exit(0);
  }
}

# fall back to legacy detection if modern detection fails
res = http_send_recv3(item:"/",
                      port:port,
                      method:"GET",
                      exit_on_fail:TRUE);

installed     = FALSE;
jenkins_ver   = NULL;
hudson_ver    = NULL;
cloudbees_ver = NULL;

# check server headers first
if ( ("X-Jenkins:" >< res[1]) || ("X-Hudson:" >< res[1]) )
{
  installed = TRUE;

  # Check for open source Jenkins
  item = eregmatch(pattern:"X-Jenkins:\s*([0-9.]+)(-SNAPSHOT)?[ \r\n]", string: res[1]);
  if (!isnull(item)) jenkins_ver = item[1];

  # Check for enterprise Jenkins (by CloudBees)
  item = eregmatch(pattern:"X-Jenkins:\s*([0-9.]+)(-SNAPSHOT)? \(Jenkins Enterprise by CloudBees ([0-9.]+)\)[ \r\n]", string: res[1]);
  if (!isnull(item))
  {
    jenkins_ver = item[1];
    cloudbees_ver = item[3];
  }

  item = eregmatch(pattern:"X-Hudson:\s*([0-9.]+)[ \r\n]", string: res[1]);
  if (!isnull(item)) hudson_ver = item[1];
}

# check result body
if (!installed)
{
  # Check for meta redirect to login page and manually follow if found
  if ("<meta http-equiv='refresh'" >< res[2])
  {
    match = eregmatch(pattern:"content='1;url=(.*)'/>", string:res[2]);
    if (!isnull(match))
    {
      link = match[1];

      res = http_send_recv3(
        method : "GET",
        port   : port,
        item   : link,
        exit_on_fail : TRUE
      );
    }
  }

  # nb: this works for enterprise Jenkins as well
  if (
    ("Welcome to Jenkins!" >< res[2] && "<title>Dashboard [Jenkins]</title>" >< res[2]) ||
    ("<title>Jenkins</title>" >< res[2] && "images/jenkins.png" >< res[2])
  ) installed = TRUE;
}

# parse version from result body
if (isnull(jenkins_ver))
{
  # Check for open source Jenkins
  item = eregmatch(pattern: "Jenkins ver.\s*([0-9.]+)(-SNAPSHOT)?\s*<", string: res[2]);
  if (!isnull(item)) jenkins_ver = item[1];

  # Check for enterprise Jenkins
  item = eregmatch(pattern: "Jenkins ver.\s*([0-9.]+)(-SNAPSHOT)?\s*\(Jenkins Enterprise by CloudBees ([0-9.]+)\)<", string: res[2]);
  if (!isnull(item))
  {
    jenkins_ver = item[1];
    cloudbees_ver = item[2];
  }
}

if (installed)
{
  set_kb_item(name:'www/Jenkins', value:TRUE);
  set_kb_item(name:"www/Jenkins/"+port+"/Installed", value:TRUE);

  if (!isnull(cloudbees_ver))
  {
    set_kb_item(name:"www/Jenkins/"+port+"/enterprise/Installed", value:TRUE);
    set_kb_item(name:"www/Jenkins/"+port+"/enterprise/CloudBeesVersion", value:cloudbees_ver);
    product = "Jenkins Enterprise by CloudBees";
    edition = "Enterprise";
  }
  else
  {
    # If no version, just call it Open Source
    if (isnull(jenkins_ver))
    {
      jenkins_ver = 'unknown';
      product = "Jenkins Open Source";
      edition = "Open Source";
    }
    else
    {
      # All LTS releases are max_index == 3
      # All non-LTS releases are max_index == 2, EXCEPT one non-LTS
      # release : 1.395.1, so do not mark that one as LTS
      if (
        (max_index(split(jenkins_ver, sep:".", keep:FALSE)) == 3) &&
        jenkins_ver != '1.395.1'
      )
      {
        product = "Jenkins Open Source LTS";
        set_kb_item(name:"www/Jenkins/" + port + "/is_LTS", value:TRUE);
        edition = "Open Source LTS";
      }
      else
      {
        product = "Jenkins Open Source";
        edition = "Open Source";
      }
    }
  }

  if (isnull(hudson_ver)) hudson_ver = 'unknown';

  set_kb_item(name:"www/Jenkins/" + port + "/JenkinsVersion", value:jenkins_ver);
  set_kb_item(name:"www/Jenkins/" + port + "/HudsonVersion", value:hudson_ver);

  extra = make_array("Edition", edition, "Hudson Version", hudson_ver);
  if (!isnull(cloudbees_ver))
    extra["CloudBees Version"] = cloudbees_ver;

  # register the install and exit
  register_install(
    app_name : appname,
    path     : '/',
    version  : jenkins_ver,
    port     : port,
    cpe      : "cpe:/a:cloudbees:jenkins",
    webapp   : TRUE,
    extra    : extra
  );
  report_installs(port:port, app_name:appname);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_INST, appname, port);
