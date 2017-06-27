#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65702);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_name(english:"Git Repository Served by Web Server");
  script_summary(english:"Detects a Git repository being served by a web server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may disclose information due to a configuration
weakness.");
  script_set_attribute(attribute:"description", value:
"The web server on the remote host allows read access to a Git
repository.  This potential flaw can be used to download content from
the Web server that might otherwise be private.");
  script_set_attribute(attribute:"solution", value:"Verify that the listed Git repositories are served intentionally.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"see_also", value:"http://www.skullsecurity.org/blog/2012/using-git-clone-to-get-pwn3d");
  # http://techcrunch.com/2009/09/23/basic-flaw-reveals-source-code-to-3300-popular-websites/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cdb772a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

global_var port;

function check_repo(dir)
{
  local_var head, refs, req, transport, type;

  head = http_send_recv3(port:port, method:"GET", item:dir + "/HEAD");
  if (isnull(head)) return NULL;

  refs = http_send_recv3(port:port, method:"GET", item:dir + "/info/refs?service=git-upload-pack");
  if (isnull(refs)) return NULL;

  # Only repositories served over Smart HTTP will include this line
  # before the rest of the output. Enabling Smart HTTP requires
  # intentional setup and configuration, indicating that the
  # repository was placed there intentionally.
  if ("001e# service=git-upload-pack" >< refs[2])
    transport = "Smart HTTP";

  # If the repository is not served over Smart HTTP, but the 'refs'
  # file exists, it indicates that 'git update-server-info' was run in
  # the remote repository to make it clonable, indicating that it is
  # intended to be shared.
  else if ("refs/" >< refs[2] && head[2] =~ "^ref: refs/")
    transport = "Plain HTTP";

  # If we got info/refs, but it doesn't have what we expect in it, the
  # repository might be empty but intentionally shared.
  else if ("200 OK" >< refs[0] && refs[2] == "" && head[2] =~ "^ref: refs/")
    transport = "Plain HTTP, possibly empty";

  # If we could not get the info/refs file (didn't get 200 OK), we assume
  # the repository was not intentionally shared.
  else if (head[2] =~ "^ref: refs/")
    transport = "Not configured for cloning";

  else
    return NULL;

  # If we find Git repository metadata files in a (sub)directory
  # called .git, we consider the repository to be not bare.
  # If we find metadata files anywhere else, we assume it is a bare
  # repository.
  if (dir =~ "/\.git$")
    type = "Non-Bare";
  else
    type = "Bare";

  return make_array(
    "directory", dir,
    "type", type,
    "transport", transport
  );
}

# Get the ports that webservers have been found on.
port = get_http_port(default:80);

# Get a list of directories discovered by other plugins.
dirs = get_kb_list("www/" + port + "/content/directories");
if (isnull(dirs)) dirs = make_list();
else dirs = make_list(dirs);

# Ensure that an entry for the webserver's root is in the list.
dirs = list_uniq(make_list(dirs, ""));

# We also want to search each directory for a .git subdirectory if it
# appears to be non-bare.
temp_list = make_list();
foreach dir (dirs)
{
  temp_list = make_list(temp_list, dir);

  if (dir !~ "\.git$")
    temp_list = make_list(temp_list, dir + "/.git");
}
dirs = temp_list;

# Fetch the files from each directory and report on them.
i = 0;
repos = make_list();
foreach dir (dirs)
{
  # Fetch the files for this directory, and analyze them.
  repo = check_repo(dir:dir);

  # If it's really a repo, add it to the list to report on.
  if (!isnull(repo))
    repos[i++] = repo;
}

# If we didn't identify any repos.
if (max_index(repos) == 0)
  audit(AUDIT_WEB_FILES_NOT, "Git configuration", port);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nThe following repositories were found on the remote web server :' +
    '\n';

  foreach repo (repos)
  {
    report +=
      '\n  Repository : ' + build_url(port:port, qs:repo["directory"]) +
      '\n  Type       : ' + repo["type"] +
      '\n  Transport  : ' + repo["transport"] +
      '\n';
  }
}

security_warning(port:port, extra:report);
