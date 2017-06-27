#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11112);
  script_version("$Revision: 1.52 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2001-0582", "CVE-2001-0680", "CVE-2001-1335", "CVE-2004-1679");
  script_bugtraq_id(11159, 2618, 2786, 38756, 44759, 5168);
  script_osvdb_id(1794, 4050, 8982, 9899, 13892);

  script_name(english:"FTP Server Traversal Arbitrary File Access");
  script_summary(english:"Attempts to get the listing of the remote root dir.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a directory traversal attack.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server allows users to browse the entire remote disk by
issuing commands with traversal style characters. An attacker could
exploit this flaw to gain access to arbitrary files.");
  # https://web.archive.org/web/20020227075045/http://archives.neohapsis.com/archives/bugtraq/2001-04/0231.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83ccf5c4");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/May/248");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/119");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/May/35");
  script_set_attribute(attribute:"solution", value:"Contact your vendor for the latest version of the FTP software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "os_fingerprint.nasl");
  script_exclude_keys("ftp/ncftpd", "ftp/msftpd");
  script_require_keys("ftp/login");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

port = get_ftp_port(default: 21);

function dir(loc, soc)
{
  local_var ls, p, r, result, soc2;

  p = ftp_pasv(socket:soc);
  if(!p) exit(1, "PASV command failed on port "+port+".");
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if(!soc2)return NULL;

  #display("Ok\n");
  ls = strcat("LIST ", loc, '\r\n');
  send(socket:soc, data:ls);
  r = recv_line(socket:soc, length:4096);
  if(ereg(pattern:"^150 ", string:r))
  {
    result = ftp_recv_listing(socket:soc2);
    close(soc2);
    r = ftp_recv_line(socket:soc);
    return(result);
  }
  close(soc2);
  return NULL;
}

# Compares two directory listings (assumes the first provided is legit).
# Returns TRUE if the lists are both valid and differ, FALSE otherwise
function list_diff()
{
  local_var a, b;
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  return
    strlen(b) &&
    ereg(pattern:"[a-zA-Z0-9]", string:b) &&
    ! match(string: b, pattern: "*permission denied*", icase: TRUE) &&
    ! match(string: b, pattern: "*no such file or directory*", icase: TRUE) &&
    ! match(string: b, pattern: "*not found*", icase: TRUE) &&
    ! match(string: b, pattern: "*total 0*", icase: TRUE) &&
    a != b;
}

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

user = get_kb_item('ftp/login');
pass = get_kb_item('ftp/password');

if (isnull(user))
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  user = 'anonymous';
}
if (isnull(pass))
{
  if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
  pass = 'nessus@' + get_host_name();
}

if(!ftp_authenticate(socket:soc, user:user, pass:pass))
  exit(1, "Cannot authenticate on port "+port+".");

# Try to access the root directory using different paths, trying a
# couple times for each path.
l2 = NULL; l1 = NULL;
foreach loc (make_list("/", "/*"))
{
  for (i = 0; i < 2 && !l2; i++)
    l2 = dir(loc:loc, soc:soc);
  if (!isnull(l2)) break;
}

if (isnull(l2))
{
  ftp_close(socket:soc);
  exit(1, "No answer for DIR / on port "+port+".");
}

# Try to access the root directory again, using the same path that
# worked last time.
for (i = 0; i < 2 && !l1; i++)
  l1 = dir(loc:loc, soc:soc);

# Ensure that the FTP server is consistently giving us the same view
# of the root directory.
if (l1 != l2)
{
  ftp_close(socket:soc);
  exit(1, "Varying output for DIR / on port "+port+".");
}

# If we know the OS the remote host is using, we can limit our
# requests. Only do this when not paranoid.
dirs = NULL;
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (!isnull(os))
  {
    if ("Windows" >< os)
      dirs = make_list("/windows");
    else
      dirs = make_list("/etc");
  }
}

# If we couldn't narrow down what to check, try everything.
if (isnull(dirs))
  dirs = make_list("/etc", "/windows");

# These are the generic traversal strings. The booleans indicate
# whether the traversal string is likely to get us back to the root
# directory.
generic = make_array(
  "../../../../../../../", TRUE,
  "..\..\..\..\..\..\..\", TRUE,
  "..%5c..%5c..%5c..%5c..%5c..%5c..%5c", TRUE,
  "\..\..\..\..\..\", TRUE,
  "...", FALSE,
  "/...", FALSE,
  "/......", FALSE,
  "\...", FALSE,
  "...\", FALSE,
  "..../", FALSE,
  "\", FALSE,
  "/", FALSE,
  "..:/..:/..:/..:/..:/..:/..:/..:/", TRUE,
  "..:\..:\..:\..:\..:\..:\..:\..:\", TRUE
);

# Transform the generic traversal strings to include directory names
# for the traversal strings that might get us to the host's root
# directory.
patterns = make_list();
foreach pattern (keys(generic))
{
  patterns = make_list(patterns, pattern);

  if (!generic[pattern]) continue;

  foreach dir (dirs)
  {
    patterns = make_list(patterns, pattern + dir);
  }
}

vuln = FALSE;

foreach pat (patterns)
{
  # First try using the dir traversal directly in the LIST command
  l2 = dir(loc: pat, soc: soc);
  vuln = list_diff(l1, l2);

  # If that didn't work, try passing the directory traversal string to
  # CWD first, and then trying a LIST
  if (!vuln)
  {
    r = ftp_send_cmd(socket:soc, cmd:'CWD '+pat);

    if (ereg(pattern:"^250 ", string:r))
    {
      l2 = dir(loc:'', soc:soc);
      vuln = list_diff(l1, l2);
      cmd = 'CWD';
    }
  }
  else cmd = 'LIST';

  if (vuln && report_paranoia < 2)
  {
    # Recheck the initial directory to make sure the change in the
    # directory listing found with the attack isn't just a
    # coincidental change in the initial directory itself.
    l3 = dir(loc:loc, soc:soc);
    if (list_diff(l1, l3) && !list_diff(l3, l2)) vuln = FALSE;
  }

  if (vuln)
  {
     #display(l1, "\n****\n"); display(l2, "\n");
     report = strcat(
       '\nThe command we found to escape the chrooted environment is : ',
       cmd, ' ', pat,
       '\n',
       '\nThis directory contains :\n\n', l2);
     security_warning(port:port, extra:report);
     ftp_close(socket: soc);
     exit(0);
  }
}
ftp_close(socket: soc);
audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', port);
