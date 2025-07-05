/*

 $Id: ssmtp.c,v 2.60 2003/08/17 14:17:57 matt Exp $

 sSMTP -- send messages via SMTP to a mailhub for local delivery or forwarding.
 This program is used in place of /usr/sbin/sendmail, called by "mail" (et all).
 sSMTP does a selected subset of sendmail's standard tasks (including exactly
 one rewriting task), and explains if you ask it to do something it can't. It
 then sends the mail to the mailhub via an SMTP connection. Believe it or not,
 this is nothing but a filter

 See COPYRIGHT for the license

*/
#define VERSION "2.60.4"

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>

#ifdef MY_FEATURE
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#endif

#ifdef HAVE_SSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif
#ifdef MD5AUTH
#include "md5auth/hmac_md5.h"
#endif
#include "ssmtp.h"


#ifdef MY_FEATURE
#define SMTP_BUF 256
#define DEBUG 1

#ifdef DEBUG
#define MARK() printf("File %s Function: %s  line: %d\n", __FILE__, __func__, __LINE__);
#define dbprintf(format, para...) printf( "%s:%s:%d: "format, __FILE__, __func__, __LINE__,##para)
#else
#define MARK()
#define dbprintf(format, para...)
#endif
#define CONNECT_TIMEOUT 30	/* if connecting is not success in 30 second, don't try to connect again*/
#define SSL_TIMEOUT 30
#define MAIL_TO_MAX 4
#define SEND_TIME_TIMEOUT 30
#define SSMTP_TEST_FILE_RESULT "/tmp/ssmtp" 
#define SSMTP_MAIL_TO_RESULT_DEFAULT "1111"	/* default all send failed */

/* ssmtp error code */
#define SSMTP_ERROR_CODE_SUCCESS 				0	/* send mail success */
#define SSMTP_ERROR_CODE_INTERNAL 			1	/* internal error */
#define SSMTP_ERROR_CODE_USERNAME 			2	/* username error */
#define SSMTP_ERROR_CODE_PASSWORD 			3	/* password error */
#define SSMTP_ERROR_CODE_NETWORK 			4	/* network error */
#define SSMTP_ERROR_CODE_SENDER				5	/* sender login failed */
#define SSMTP_ERROR_CODE_ENCRYPT				6	/* encrypt error */
#define SSMTP_ERROR_CODE_SERVER				7	/* smtp server error */	
#define SSMTP_ERROR_CODE_NO_ATTACHMENT		8	/* smtp no attachment error */
#define SSMTP_ERROR_CODE_RECEIVER				9	/* all receivers are error */
#define SSMTP_ERROR_CODE_UNKOWN				10	/* unknown error */	
#define SSMTP_ERROR_CODE_RECEIVER_FAILED		"1"	/* receiver error */
#define SSMTP_ERROR_CODE_RECEIVER_SUCCESS	"0"	/* receiver success */
#define FILEMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

char *isTest = NULL;

static int cram_md5_flag = 0;
static int auth_plain_flag = 0;
static int auth_login_flag = 1; /* default support,and try it at last */
static char *attachment_path = NULL;
static char *config_file_path = NULL;
static char recipients[SMTP_BUF+1];
static char *subject = "";
static char *text_body = "";
static char attachment_name[MAX_SZ];
static unsigned char media_data[MAX_ATTACHMENT_LEN];
static int attachment_length;
static char sender[SMTP_BUF]; 
#endif /* MY_FEATURE */



bool_t have_date = False;
bool_t have_from = False;
#ifdef HASTO_OPTION
bool_t have_to = False;
#endif
bool_t minus_t = False;
bool_t minus_v = False;
bool_t override_from = False;
bool_t rewrite_domain = False;
bool_t use_tls = False;			/* Use SSL to transfer mail to HUB */
bool_t use_starttls = False;		/* SSL only after STARTTLS (RFC2487) */
bool_t use_cert = False;		/* Use a certificate to transfer SSL mail */

#define ARPADATE_LENGTH 32		/* Current date in RFC format */
char arpadate[ARPADATE_LENGTH];

#ifdef MY_FEATURE
char auth_user[SMTP_BUF];
char auth_pass[SMTP_BUF];
char auth_method[SMTP_BUF];		/* Mechanism for SMTP authentication */
char mail_domain[SMTP_BUF];
char mailhost[SMTP_BUF]="mailhub";
char tls_cert[SMTP_BUF] = "/etc/ssl/certs/ssmtp.pem";	/* Default Certificate */
#else
char *auth_user=NULL;
char *auth_pass = NULL;
char *auth_method = NULL;		/* Mechanism for SMTP authentication */
char *mail_domain = NULL;
char *mailhost = "mailhub";
char *tls_cert = "/etc/ssl/certs/ssmtp.pem";	/* Default Certificate */
#endif
char *gecos;
char *from=NULL;				/* Use this as the From: address */
char hostname[MAXHOSTNAMELEN] = "localhost";
char *minus_f = NULL;
char *minus_F = NULL;
char *prog = NULL;
char *root = NULL;
char *uad = NULL;

headers_t headers, *ht;

#ifdef DEBUG
int log_level = 1;
#else
int log_level = 0;
#endif
int port = 25;
#ifdef INET6
int p_family = PF_UNSPEC;		/* Protocol family used in SMTP connection */
#endif

jmp_buf TimeoutJmpBuf;			/* Timeout waiting for input from network */

rcpt_t rcpt_list, *rt;

#ifdef HAVE_SSL
SSL *ssl;
#endif

#ifdef MD5AUTH
static char hextab[]="0123456789abcdef";
#endif


/*
log_event() -- Write event to syslog (or log file if defined)
*/
void log_event(int priority, char *format, ...)
{
	char buf[(BUF_SZ + 1)];
	va_list ap;

	va_start(ap, format);
	(void)vsnprintf(buf, BUF_SZ, format, ap);
	va_end(ap);

#ifdef LOGFILE
	FILE *fp;

	if((fp = fopen("/tmp/ssmtp.log", "a")) != (FILE *)NULL) {
		(void)fprintf(fp, "%s\n", buf);
		(void)fclose(fp);
	}
	else {
		(void)fprintf(stderr, "Can't write to /tmp/ssmtp.log\n");
	}
#endif

#if HAVE_SYSLOG_H
#if OLDSYSLOG
	openlog("sSMTP", LOG_PID);
#else
	openlog("sSMTP", LOG_PID, LOG_MAIL);
#endif
	syslog(priority, "%s", buf);
	closelog();
#endif
}

void smtp_write(int fd, char *format, ...);
int smtp_read(int fd, char *response);
int smtp_read_all(int fd, char *response);
int smtp_okay(int fd, char *response);

#ifdef MY_FEATURE
/* lock fd */
int myLock(int fd, int type)
{
	struct flock lock;
	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	return fcntl(fd, F_SETLKW, &lock);
}

/* unlock fd */
int myUnLock(int fd)
{
	struct flock lock;
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	return fcntl(fd,F_SETLKW, &lock);
}

/*
 *	write the InputString to FilePath
 */
int WriteStringToFile(char *FilePath,char *InputString,int Len)
{
	int fd;

	if(NULL == FilePath || NULL == InputString)
	{
		return -1;

	}

	if(0 > (fd = open(FilePath,O_WRONLY | O_TRUNC | O_CREAT,FILEMODE)))
	{
		return -1;
	}

	if(0 > myLock(fd,F_WRLCK))
	{
		close(fd);
		return -1;
	}
	
	if(0 > write(fd,InputString,Len))
	{
		myUnLock(fd);
		close(fd);
		return -1;
	}

	myUnLock(fd);
	close(fd);
	
	return 0;
}
#endif

/*
dead_letter() -- Save stdin to ~/dead.letter if possible
*/
void dead_letter(void)
{
	char path[(MAXPATHLEN + 1)], buf[(BUF_SZ + 1)];
	struct passwd *pw;
	uid_t uid;
	FILE *fp;

	uid = getuid();
	pw = getpwuid(uid);

	if(isatty(fileno(stdin))) {
		if(log_level > 0) {
			log_event(LOG_ERR,
				"stdin is a TTY - not saving to %s/dead.letter, pw->pw_dir");
		}
		return;
	}

	if(pw == (struct passwd *)NULL) {
		/* Far to early to save things */
		if(log_level > 0) {
			log_event(LOG_ERR, "No sender failing horribly!");
		}
		return;
	}

	if(snprintf(path, BUF_SZ, "%s/dead.letter", pw->pw_dir) == -1) {
		/* Can't use die() here since dead_letter() is called from die() */
		exit(1);
	}

	if((fp = fopen(path, "a")) == (FILE *)NULL) {
		/* Perhaps the person doesn't have a homedir... */
		if(log_level > 0) {
			log_event(LOG_ERR, "Can't open %s failing horribly!", path);
		}
		return;
	}

	/* We start on a new line with a blank line separating messages */
	(void)fprintf(fp, "\n\n");

	while(fgets(buf, sizeof(buf), stdin)) {
		(void)fputs(buf, fp);
	}

	if(fclose(fp) == -1) {
		if(log_level > 0) {
			log_event(LOG_ERR,
				"Can't close %s/dead.letter, possibly truncated", pw->pw_dir);
		}
	}
}

#ifdef MY_FEATURE
void myFree()
{
	if (gecos)
	{
		free(gecos);
		gecos = NULL;
	}

	if (uad)
	{
		free(uad);
		uad = NULL;
	}
	
	if (from)
	{
		free(from);
		from = NULL;
	}
}
#endif

/*
die() -- Write error message, dead.letter and exit
*/
void die(char *format, ...)
{
	char buf[(BUF_SZ + 1)];
	va_list ap;

	va_start(ap, format);
	(void)vsnprintf(buf, BUF_SZ, format, ap);
	va_end(ap);

	(void)fprintf(stderr, "%s: %s\n", prog, buf);
	log_event(LOG_ERR, "%s", buf);

	/* Send message to dead.letter */
	(void)dead_letter();

#ifdef MY_FEATURE
	myFree();
#endif

	exit(1);
}

/*
basename() -- Return last element of path
*/
char *basename(char *str)
{
	char buf[MAXPATHLEN +1], *p;

	if((p = strrchr(str, '/'))) {
		if(strncpy(buf, ++p, MAXPATHLEN) == (char *)NULL) {
			die("basename() -- strncpy() failed");
		}
	}
	else {
		if(strncpy(buf, str, MAXPATHLEN) == (char *)NULL) {
			die("basename() -- strncpy() failed");
		}
	}
	buf[MAXPATHLEN] = 0;

	return(strdup(buf));
}

/*
strip_pre_ws() -- Return pointer to first non-whitespace character
*/
char *strip_pre_ws(char *str)
{
	char *p;

	p = str;
	while(*p && isspace(*p)) p++;

	return(p);
}

/*
strip_post_ws() -- Return pointer to last non-whitespace character
*/
char *strip_post_ws(char *str)
{
	char *p;

	p = (str + strlen(str));
	while(isspace(*--p)) {
		*p = 0;
	}

	return(p);
}

/*
addr_parse() -- Parse <user@domain.com> from full email address
*/
char *addr_parse(char *str)
{
	char *p, *q;

#if 0
	(void)fprintf(stderr, "*** addr_parse(): str = [%s]\n", str);
#endif

	/* Simple case with email address enclosed in <> */
	if((p = strdup(str)) == (char *)NULL) {
		die("addr_parse(): strdup()");
	}

	if((q = strchr(p, '<'))) {
		q++;

		if((p = strchr(q, '>'))) {
			*p = 0;
		}

#if 0
		(void)fprintf(stderr, "*** addr_parse(): q = [%s]\n", q);
#endif

		return(q);
	}

	q = strip_pre_ws(p);
	if(*q == '(') {
		while((*q++ != ')'));
	}
	p = strip_pre_ws(q);

#if 0
	(void)fprintf(stderr, "*** addr_parse(): p = [%s]\n", p);
#endif

	q = strip_post_ws(p);
	if(*q == ')') {
		while((*--q != '('));
		*q = 0;
	}
	(void)strip_post_ws(p);

#if 0
	(void)fprintf(stderr, "*** addr_parse(): p = [%s]\n", p);
#endif

	return(p);
}

/*
append_domain() -- Fix up address with @domain.com
*/
char *append_domain(char *str)
{
	char buf[(BUF_SZ + 1)];

	if(strchr(str, '@') == (char *)NULL) {
		if(snprintf(buf, BUF_SZ, "%s@%s", str,
#ifdef REWRITE_DOMAIN
			rewrite_domain == True ? mail_domain : hostname
#else
			hostname
#endif
														) == -1) {
				die("append_domain() -- snprintf() failed");
		}
		return(strdup(buf));
	}

	return(strdup(str));
}

/*
standardise() -- Trim off '\n's and double leading dots
*/
void standardise(char *str)
{
	size_t sl;
	char *p;

	if((p = strchr(str, '\n'))) {
		*p = 0;
	}

	/* Any line beginning with a dot has an additional dot inserted;
	not just a line consisting solely of a dot. Thus we have to slide
	the buffer down one */
	sl = strlen(str);

	if(*str == '.') {
		if((sl + 2) > BUF_SZ) {
			die("standardise() -- Buffer overflow");
		}
		(void)memmove((str + 1), str, (sl + 1));	/* Copy trailing \0 */

		*str = '.';
	}
}

/*
revaliases() -- Parse the reverse alias file
	Fix globals to use any entry for sender
*/
void revaliases(struct passwd *pw)
{
	char buf[(BUF_SZ + 1)], *p;
	FILE *fp;

	/* Try to open the reverse aliases file */
	if((fp = fopen(REVALIASES_FILE, "r"))) {
		/* Search if a reverse alias is defined for the sender */
		while(fgets(buf, sizeof(buf), fp)) {
			/* Make comments invisible */
			if((p = strchr(buf, '#'))) {
				*p = 0;
			}

			/* Ignore malformed lines and comments */
			if(strchr(buf, ':') == (char *)NULL) {
				continue;
			}

			/* Parse the alias */
			if(((p = strtok(buf, ":"))) && !strcmp(p, pw->pw_name)) {
				if((p = strtok(NULL, ": \t\r\n"))) {
					if((uad = strdup(p)) == (char *)NULL) {
						die("revaliases() -- strdup() failed");
					}
				}
#ifdef MY_FEATURE
			if((p = strtok(NULL, " \t\r\n:"))) {
					memset(mailhost, '\0', sizeof(mailhost));
					strncpy(mailhost, p, sizeof(mailhost) - 1);
#else
				if((p = strtok(NULL, " \t\r\n:"))) {
					if((mailhost = strdup(p)) == (char *)NULL) {
						die("revaliases() -- strdup() failed");
					}
#endif

					if((p = strtok(NULL, " \t\r\n:"))) {
						port = atoi(p);
					}

					if(log_level > 0) {
						log_event(LOG_INFO, "Set MailHub=\"%s\"\n", mailhost);
						log_event(LOG_INFO,
							"via SMTP Port Number=\"%d\"\n", port);
					}
				}
			}
		}

		fclose(fp);
	}
}

/* 
from_strip() -- Transforms "Name <login@host>" into "login@host" or "login@host (Real name)"
*/
char *from_strip(char *str)
{
	char *p;

#if 0
	(void)fprintf(stderr, "*** from_strip(): str = [%s]\n", str);
#endif

	if(strncmp("From:", str, 5) == 0) {
		str += 5;
	}

	/* Remove the real name if necessary - just send the address */
	if((p = addr_parse(str)) == (char *)NULL) {
		die("from_strip() -- addr_parse() failed");
	}
#if 0
	(void)fprintf(stderr, "*** from_strip(): p = [%s]\n", p);
#endif

	return(strdup(p));
}

/*
from_format() -- Generate standard From: line
*/
char *from_format(char *str, bool_t override_from)
{
	char buf[(BUF_SZ + 1)];

	if(override_from) {
		if(minus_f) {
			str = append_domain(minus_f);
		}

		if(minus_F) {
			if(snprintf(buf,
				BUF_SZ, "\"%s\" <%s>", minus_F, str) == -1) {
				die("from_format() -- snprintf() failed");
			}
		}
		else if(gecos) {
			if(snprintf(buf, BUF_SZ, "\"%s\" <%s>", gecos, str) == -1) {
				die("from_format() -- snprintf() failed");
			}
		}
		else {
			if(snprintf(buf, BUF_SZ, "%s", str) == -1) {
				die("from_format() -- snprintf() failed");
			}
		}
	}
	else {
		if(gecos) {
			if(snprintf(buf, BUF_SZ, "\"%s\" <%s>", gecos, str) == -1) {
				die("from_format() -- snprintf() failed");
			}
		}
	}

#if 0
	(void)fprintf(stderr, "*** from_format(): buf = [%s]\n", buf);
#endif

	return(strdup(buf));
}

/*
rcpt_save() -- Store entry into RCPT list
*/
void rcpt_save(char *str)
{
	char *p;

# if 1
	/* Horrible botch for group stuff */
	p = str;
	while(*p) p++;

	if(*--p == ';') {
		return;
	}
#endif

#if 0
	(void)fprintf(stderr, "*** rcpt_save(): str = [%s]\n", str);
#endif

	/* Ignore missing usernames */
	if(*str == 0) {
		return;
	}

	if((rt->string = strdup(str)) == (char *)NULL) {
		die("rcpt_save() -- strdup() failed");
	}

	rt->next = (rcpt_t *)malloc(sizeof(rcpt_t));
	if(rt->next == (rcpt_t *)NULL) {
		die("rcpt_save() -- malloc() failed");
	}
	rt = rt->next;

	rt->next = (rcpt_t *)NULL;
}

/*
rcpt_parse() -- Break To|Cc|Bcc into individual addresses
*/
void rcpt_parse(char *str)
{
	bool_t in_quotes = False, got_addr = False;
	char *p, *q, *r;

#if 0
	(void)fprintf(stderr, "*** rcpt_parse(): str = [%s]\n", str);
#endif

	if((p = strdup(str)) == (char *)NULL) {
		die("rcpt_parse(): strdup() failed");
	}
	q = p;

	/* Replace <CR>, <LF> and <TAB> */
	while(*q) {
		switch(*q) {
			case '\t':
			case '\n':
			case '\r':
					*q = ' ';
		}
		q++;
	}
	q = p;

#if 0
	(void)fprintf(stderr, "*** rcpt_parse(): q = [%s]\n", q);
#endif

	r = q;
	while(*q) {
		if(*q == '"') {
			in_quotes = (in_quotes ? False : True);
		}

		/* End of string? */
		if(*(q + 1) == 0) {
			got_addr = True;
		}

		/* End of address? */
		if((*q == ',') && (in_quotes == False)) {
			got_addr = True;

			*q = 0;
		}

		if(got_addr) {
			while(*r && isspace(*r)) r++;

			rcpt_save(addr_parse(r));
			r = (q + 1);
#if 0
			(void)fprintf(stderr, "*** rcpt_parse(): r = [%s]\n", r);
#endif
			got_addr = False;
		}
		q++;
	}
	free(p);
}

#ifdef MD5AUTH
int crammd5(char *challengeb64, char *username, char *password, char *responseb64)
{
	int i;
	unsigned char digest[MD5_DIGEST_LEN];
	unsigned char digascii[MD5_DIGEST_LEN * 2 +1];
	unsigned char challenge[(BUF_SZ + 1)];
	unsigned char response[(BUF_SZ + 1)];
	unsigned char secret[(MD5_BLOCK_LEN + 1)]; 

	memset ((char *)secret,0,sizeof(secret));
	memset ((char *)challenge,0,sizeof(challenge));
	strncpy ((char *)secret, password, sizeof(secret));	
	if (!challengeb64 || strlen(challengeb64) > sizeof(challenge) * 3 / 4)
		return 0;
	from64tobits((char *)challenge, challengeb64);

	hmac_md5(challenge, strlen((char *)challenge), secret, strlen((char *)secret), digest);

	for (i = 0; i < MD5_DIGEST_LEN; i++) {
		digascii[2 * i] = hextab[digest[i] >> 4];
		digascii[2 * i + 1] = hextab[(digest[i] & 0x0F)];
	}
	digascii[MD5_DIGEST_LEN * 2] = '\0';

	if (sizeof(response) <= strlen(username) + sizeof(digascii))
		return 0;
	
	strncpy ((char *)response, username, sizeof(response) - sizeof(digascii) - 2);
	strcat ((char *)response, " ");
	strcat ((char *)response, (char *)digascii);
	to64frombits((unsigned char *)responseb64, response, strlen((char *)response));

	return 1;
}
#endif

/*
rcpt_remap() -- Alias systems-level users to the person who
	reads their mail. This is variously the owner of a workstation,
	the sysadmin of a group of stations and the postmaster otherwise.
	We don't just mail stuff off to root on the mailhub :-)
*/
char *rcpt_remap(char *str)
{
	struct passwd *pw;
	if((root==NULL) || strlen(root)==0 || strchr(str, '@') ||
		((pw = getpwnam(str)) == NULL) || (pw->pw_uid > MAXSYSUID)) {
		return(append_domain(str));	/* It's not a local systems-level user */
	}
	else {
		return(append_domain(root));
	}
}

/*
header_save() -- Store entry into header list
*/
void header_save(char *str)
{
	char *p;

#if 0
	(void)fprintf(stderr, "header_save(): str = [%s]\n", str);
#endif

	if((p = strdup(str)) == (char *)NULL) {
		die("header_save() -- strdup() failed");
	}
	ht->string = p;

	if(strncasecmp(ht->string, "From:", 5) == 0) {
#if 1
		/* Hack check for NULL From: line */
		if(*(p + 6) == 0) {
			return;
		}
#endif

#ifdef REWRITE_DOMAIN
		if(override_from == True) {
			uad = from_strip(ht->string);
		}
		else {
			return;
		}
#endif
		have_from = True;
	}
#ifdef HASTO_OPTION
	else if(strncasecmp(ht->string, "To:" ,3) == 0) {
		have_to = True;
	}
#endif
	else if(strncasecmp(ht->string, "Date:", 5) == 0) {
		have_date = True;
	}

	if(minus_t) {
		/* Need to figure out recipients from the e-mail */
		if(strncasecmp(ht->string, "To:", 3) == 0) {
			p = (ht->string + 3);
			rcpt_parse(p);
		}
		else if(strncasecmp(ht->string, "Bcc:", 4) == 0) {
			p = (ht->string + 4);
			rcpt_parse(p);
		}
		else if(strncasecmp(ht->string, "CC:", 3) == 0) {
			p = (ht->string + 3);
			rcpt_parse(p);
		}
	}

#if 0
	(void)fprintf(stderr, "header_save(): ht->string = [%s]\n", ht->string);
#endif

	ht->next = (headers_t *)malloc(sizeof(headers_t));
	if(ht->next == (headers_t *)NULL) {
		die("header_save() -- malloc() failed");
	}
	ht = ht->next;

	ht->next = (headers_t *)NULL;
}

/*
header_parse() -- Break headers into seperate entries
*/
void header_parse(FILE *stream)
{
	size_t size = BUF_SZ, len = 0;
	char *p = (char *)NULL, *q = (char *)NULL;
	bool_t in_header = True;
	char l = 0;
	int c;

	while(in_header && ((c = fgetc(stream)) != EOF)) {
		/* Must have space for up to two more characters, since we
			may need to insert a '\r' */
		if((p == (char *)NULL) || (len >= (size - 1))) {
			size += BUF_SZ;

			p = (char *)realloc(p, (size * sizeof(char)));
			if(p == (char *)NULL) {
				die("header_parse() -- realloc() failed");
			}
			q = (p + len);
		}
		len++;

		if(l == '\n') {
			switch(c) {
				case ' ':
				case '\t':
						/* Must insert '\r' before '\n's embedded in header
						   fields otherwise qmail won't accept our mail
						   because a bare '\n' violates some RFC */
						
						*(q - 1) = '\r';	/* Replace previous \n with \r */
						*q++ = '\n';		/* Insert \n */
						len++;
						
						break;

				case '\n':
						in_header = False;

				default:
						*q = 0;
						if((q = strrchr(p, '\n'))) {
							*q = 0;
						}
						header_save(p);

						q = p;
						len = 0;
			}
		}
		*q++ = c;

		l = c;
	}
	(void)free(p);
}


#ifndef MY_FEATURE
/*
read_config() -- Open and parse config file and extract values of variables
*/
bool_t read_config()
{
	char buf[(BUF_SZ + 1)], *p, *q, *r;
	FILE *fp;

	if((fp = fopen(CONFIGURATION_FILE, "r")) == NULL) {
		return(False);
	}

	while(fgets(buf, sizeof(buf), fp)) {
		/* Make comments invisible */
		if((p = strchr(buf, '#'))) {
			*p = 0;
		}

		/* Ignore malformed lines and comments */
		if(strchr(buf, '=') == (char *)NULL) continue;

		/* Parse out keywords */
		if(((p = strtok(buf, "= \t\n")) != (char *)NULL)
			&& ((q = strtok(NULL, "= \t\n:")) != (char *)NULL)) {
			if(strcasecmp(p, "Root") == 0) {
				if((root = strdup(q)) == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set Root=\"%s\"\n", root);
				}
			}
			else if(strcasecmp(p, "MailHub") == 0) {
				if((mailhost = strdup(q)) == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}

				if((r = strtok(NULL, "= \t\n:")) != NULL) {
					port = atoi(r);
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set MailHub=\"%s\"\n", mailhost);
					log_event(LOG_INFO, "Set RemotePort=\"%d\"\n", port);
				}
			}
			else if(strcasecmp(p, "HostName") == 0) {
				if(strncpy(hostname, q, MAXHOSTNAMELEN) == NULL) {
					die("parse_config() -- strncpy() failed");
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set HostName=\"%s\"\n", hostname);
				}
			}
#ifdef REWRITE_DOMAIN
			else if(strcasecmp(p, "RewriteDomain") == 0) {
				if((p = strrchr(q, '@'))) {
					mail_domain = strdup(++p);

					log_event(LOG_ERR,
						"Set RewriteDomain=\"%s\" is invalid\n", q);
					log_event(LOG_ERR,
						"Set RewriteDomain=\"%s\" used\n", mail_domain);
				}
				else {
					mail_domain = strdup(q);
				}

				if(mail_domain == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}
				rewrite_domain = True;

				if(log_level > 0) {
					log_event(LOG_INFO,
						"Set RewriteDomain=\"%s\"\n", mail_domain);
				}
			}
#endif
			else if(strcasecmp(p, "FromLineOverride") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					override_from = True;
				}
				else {
					override_from = False;
				}

				if(log_level > 0) {
					log_event(LOG_INFO,
						"Set FromLineOverride=\"%s\"\n",
						override_from ? "True" : "False");
				}
			}
			else if(strcasecmp(p, "RemotePort") == 0) {
				port = atoi(q);

				if(log_level > 0) {
					log_event(LOG_INFO, "Set RemotePort=\"%d\"\n", port);
				}
			}
#ifdef HAVE_SSL
			else if(strcasecmp(p, "UseTLS") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					use_tls = True;
				}
				else {
					use_tls = False;
					use_starttls = False;
				}

				if(log_level > 0) { 
					log_event(LOG_INFO,
						"Set UseTLS=\"%s\"\n", use_tls ? "True" : "False");
				}
			}
			else if(strcasecmp(p, "UseSTARTTLS") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					use_starttls = True;
					use_tls = True;
				}
				else {
					use_starttls = False;
				}

				if(log_level > 0) { 
					log_event(LOG_INFO,
						"Set UseSTARTTLS=\"%s\"\n", use_tls ? "True" : "False");
				}
			}
			else if(strcasecmp(p, "UseTLSCert") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					use_cert = True;
				}
				else {
					use_cert = False;
				}

				if(log_level > 0) {
					log_event(LOG_INFO,
						"Set UseTLSCert=\"%s\"\n",
						use_cert ? "True" : "False");
				}
			}
			else if(strcasecmp(p, "TLSCert") == 0) {
				if((tls_cert = strdup(q)) == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set TLSCert=\"%s\"\n", tls_cert);
				}
			}
#endif
			/* Command-line overrides these */
			else if(strcasecmp(p, "AuthUser") == 0 && !auth_user) {
				if((auth_user = strdup(q)) == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set AuthUser=\"%s\"\n", auth_user);
				}
			}
			else if(strcasecmp(p, "AuthPass") == 0 && !auth_pass) {
				if((auth_pass = strdup(q)) == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set AuthPass=\"%s\"\n", auth_pass);
				}
			}
			else if(strcasecmp(p, "AuthMethod") == 0 && !auth_method) {
				if((auth_method = strdup(q)) == (char *)NULL) {
					die("parse_config() -- strdup() failed");
				}

				if(log_level > 0) {
					log_event(LOG_INFO, "Set AuthMethod=\"%s\"\n", auth_method);
				}
			}
			else {
				log_event(LOG_INFO, "Unable to set %s=\"%s\"\n", p, q);
			}
		}
	}
	(void)fclose(fp);

	return(True);
}
#endif /* MY_FEATURE */

#ifdef MY_FEATURE
/*
my_read_config() -- Open and parse config file and extract values of variables
*/
bool_t my_read_config()
{
	char buf[(BUF_SZ + 1)], *p, *q, *r;
	FILE *fp;

	if((fp = fopen(config_file_path, "r")) == NULL) {
		return(False);
	}

	while(fgets(buf, sizeof(buf), fp)) {
		/* Ignore malformed lines and comments */
		if(strchr(buf, '=') == (char *)NULL) continue;

		/* Parse out keywords */
		if(((p = strtok(buf, "=\t\n")) != (char *)NULL)
			&& ((q = strtok(NULL, "\t\n")) != (char *)NULL)) {
			if(strcasecmp(p, "SMTP_MAILHUB") == 0) {
				dbprintf("q is %s\n", q);
				if((r = strtok(q, ":")) != NULL) 
				{
				}
				memset(mailhost, '\0', sizeof(mailhost));
				strncpy(mailhost, q, sizeof(mailhost) - 1);
				if((r = strtok(NULL, ":")) != NULL) {
					dbprintf("r is %s\n", r);
					port = atoi(r);
				}
			}
#ifdef HAVE_SSL
			else if(strcasecmp(p, "SMTP_USE_TLS") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					use_tls = True;
				}
				else {
					use_tls = False;
					use_starttls = False;
				}
			}
			else if(strcasecmp(p, "SMTP_USE_STARTTLS") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					use_starttls = True;
					use_tls = True;
				}
				else {
					use_starttls = False;
				}
			}
			else if(strcasecmp(p, "UseTLSCert") == 0) {
				if(strcasecmp(q, "YES") == 0) {
					use_cert = True;
				}
				else {
					use_cert = False;
				}
			}
			else if(strcasecmp(p, "TLSCert") == 0) {
				memset(tls_cert, '\0', sizeof(tls_cert));
				strncpy(tls_cert, q, sizeof(tls_cert) - 1);
			}
#endif
			/* Command-line overrides these */
			else if(strcasecmp(p, "SMTP_AUTH_USER") == 0) {
				memset(auth_user, '\0', sizeof(auth_user));
				strncpy(auth_user, q, sizeof(auth_user) - 1);
			}
			else if(strcasecmp(p, "SMTP_AUTH_PASSWORD") == 0) {
				memset(auth_pass, '\0', sizeof(auth_pass));
				strncpy(auth_pass, q, sizeof(auth_pass) - 1);
			}
			else if(strcasecmp(p, "SMTP_AUTH_METHOD") == 0) {
				memset(auth_method, '\0', sizeof(auth_method));
				strncpy(auth_method, q, sizeof(auth_method) - 1);
			}
			else if(strcasecmp(p, "SMTP_TO") == 0) {
				memset(recipients, '\0', sizeof(recipients));
				strncpy(recipients, q, sizeof(recipients) - 1);
			}
			else if(strcasecmp(p, "SMTP_FROM") == 0) {
				memset(sender, '\0', sizeof(sender));
				strncpy(sender, q, sizeof(sender) - 1);
			}
			else {
				log_event(LOG_INFO, "Unable to set %s=\"%s\"\n", p, q);
			}
		}
	}

	dbprintf("mailhost is %s port is %d, auth_user is %s auth_pass is %s auth_method is %s recipients is %s and sender is %s\n", 
				mailhost, port, auth_user,auth_pass,auth_method,recipients,sender);
	
	(void)fclose(fp);

	return(True);
}
#endif /* MY_FEATURE */



#ifdef MY_FEATURE
/* set connect timeout, if timeout <=0, just connect, others, 
 *  if connect success, return 0; others, return -1
 */
int myConnect(int fd, struct sockaddr *addr, int addr_len, int timeout)
{
	int error;
	int len;
	int ret;
	
	if (NULL == addr)
	{
		return -1;
	}

	if (0 >= timeout)
	{
		return connect(fd, addr, addr_len);
	}
	
	/* set fd to no block */
	int flags = fcntl(fd,F_GETFL,0); 
	fcntl(fd,F_SETFL,flags | O_NONBLOCK); 
	
	int n = connect(fd,addr,addr_len);
	if(0 > n) 
	{ 
		/* EINPROGRESS shows trying connection */
		if(errno != EINPROGRESS && errno != EWOULDBLOCK)
		{
		    return -1; 
		}

		struct timeval tv; 
		tv.tv_sec = timeout; 
		tv.tv_usec = 0; 
		fd_set wset; 
		FD_ZERO(&wset); 
		FD_SET(fd,&wset); 
		n = select(fd+1,NULL,&wset,NULL,&tv); 
		if(n < 0) 
		{ 
			perror("select()"); 
			close(fd); 
			return -1; 
		} 
		else if (0 == n) 
		{
			dbprintf("connect timeout\n");
			close(fd); 
			return -1; 
		} 
		else 
		{
			/* test if connected */
			if (0 == getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len))
			{
				if(0 == error) 
				{
					dbprintf("connect success\n");
					ret = 0;
				}
				else
				{
					ret = -1;
				}
			}
			else
			{
				perror("getsockopt error\n");
				close(fd);
				ret = -1;
			}
		} 
	} 
	else
	{
		dbprintf("connect success\n");
		ret = 0;
	}

	/* set fd to block */
	fcntl(fd,F_SETFL,flags & ~O_NONBLOCK); 

	return ret;
}

#endif


/*
smtp_open() -- Open connection to a remote SMTP listener
*/
int smtp_open(char *host, int port)
{
#ifdef INET6
	struct addrinfo hints, *ai0, *ai;
	char servname[NI_MAXSERV];
	int s;
#else
	struct sockaddr_in name;
	struct hostent *hent;
	int s, namelen;
#endif

#ifdef HAVE_SSL
	int err;
	char buf[(BUF_SZ + 1)];

	/* Init SSL stuff */
	SSL_CTX *ctx;
	SSL_METHOD *meth;
	X509 *server_cert;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth=(SSL_METHOD *)SSLv23_client_method();
	ctx = SSL_CTX_new(meth);
	if(!ctx) {
		log_event(LOG_ERR, "No SSL support initiated\n");
		return(-1);
	}

	if(use_cert == True) { 
		if(SSL_CTX_use_certificate_chain_file(ctx, tls_cert) <= 0) {
			perror("Use certfile");
			return(-1);
		}

		if(SSL_CTX_use_PrivateKey_file(ctx, tls_cert, SSL_FILETYPE_PEM) <= 0) {
			perror("Use PrivateKey");
			return(-1);
		}

		if(!SSL_CTX_check_private_key(ctx)) {
			dbprintf("Private key does not match the certificate public key\n");
			return(-1);
		}
	}

#endif

#ifdef INET6
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = p_family;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(servname, sizeof(servname), "%d", port);

	dbprintf("before getaddrinfo\n");
	/* Check we can reach the host */
	if (getaddrinfo(host, servname, &hints, &ai0)) {
		log_event(LOG_ERR, "Unable to locate %s", host);
		dbprintf("getaddrinfo failed\n");
		return(-1);
	}
	dbprintf("after getaddrinfo\n");

	for (ai = ai0; ai; ai = ai->ai_next) {
		/* Create a socket for the connection */
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0) {
			continue;
		}

#ifdef MY_FEATURE
		if (myConnect(s, &(ai->ai_addr), ai->ai_addrlen, CONNECT_TIMEOUT) < 0) {
			s = -1;
			continue;
		}
#else
		if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			s = -1;
			continue;
		}
#endif
		break;
	}

	if(s < 0) {
		log_event (LOG_ERR,
			"Unable to connect to \"%s\" port %d.\n", host, port);
		return(-1);
	}
#else
	/* Check we can reach the host */
	dbprintf("before gethostbyname\n");
	if((hent = gethostbyname(host)) == (struct hostent *)NULL) {
		log_event(LOG_ERR, "Unable to locate %s", host);
		dbprintf("gethostbyname failed \n");
		return(-1);
	}
	dbprintf("after gethostbyname\n");

	if(hent->h_length > sizeof(hent->h_addr)) {
		dbprintf("Buffer overflow in gethostbyname()");
		return(-1);
	}

	/* Create a socket for the connection */
	if((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		dbprintf( "Unable to create a socket");
		return(-1);
	}

	/* This SHOULD already be in Network Byte Order from gethostbyname() */
	name.sin_addr.s_addr = ((struct in_addr *)(hent->h_addr))->s_addr;
	name.sin_family = hent->h_addrtype;
	name.sin_port = htons(port);

	namelen = sizeof(struct sockaddr_in);

#ifdef MY_FEATURE
		dbprintf("before my_connect\n");
		if (0 > myConnect(s, (struct sockaddr *)&name, namelen, CONNECT_TIMEOUT))
		{
			dbprintf( "Unable to connect to %s:%d", host, port);
			return(-1);
		}
#else
	if(connect(s, (struct sockaddr *)&name, namelen) < 0) {
		dbprintf( "Unable to connect to %s:%d", host, port);
		return(-1);
	}
#endif

#endif

#ifdef HAVE_SSL
	dbprintf("before use_tls\n");
	if(use_tls == True) {
		dbprintf("used tls\n");
		log_event(LOG_INFO, "Creating SSL connection to host");

		if (use_starttls == True)
		{
			use_tls=False; /* need to write plain text for a while */
			dbprintf("before smtp okey\n");
			if (smtp_okay(s, buf))
			{
				dbprintf("after smtp okey\n");
				smtp_write(s, "EHLO %s", hostname);
				dbprintf("hostname is %s\n", hostname);
				if (smtp_okay(s, buf)) {
					smtp_write(s, "STARTTLS"); /* assume STARTTLS regardless */
					if (!smtp_okay(s, buf)) {
						dbprintf( "STARTTLS not working");
						return(-1);
					}
				}
				else
				{
					dbprintf("Invalid response: %s (%s)", buf, hostname);
					smtp_write(s, "EHLO %s", auth_user);
					if (smtp_okay(s, buf)) {
						smtp_write(s, "STARTTLS"); /* assume STARTTLS regardless */
						if (!smtp_okay(s, buf)) {
							dbprintf( "STARTTLS not working");
							return(-1);
						}
					}
					else
					{
						dbprintf("Invalid response: %s (%s)", buf, auth_user);
						return (-1);
					}
				}
			}
			else
			{
				dbprintf("Invalid response SMTP Server (STARTTLS)");
				return(-1);
			}
			dbprintf("after smtp okey\n");
			use_tls=True; /* now continue as normal for SSL */

		}

		dbprintf("before SSL_new\n");
		ssl = SSL_new(ctx);
		if(!ssl) {
			dbprintf( "SSL not working");
			return(-1);
		}

		SSL_set_fd(ssl, s);
		dbprintf("before ssl connect\n");
		err = SSL_connect(ssl);
		if(err < 0) {
			perror("SSL_connect");
			return(-1);
		}
		dbprintf("after ssl connect\n");

		if(log_level > 0 || 1) {
			log_event(LOG_INFO, "SSL connection using %s",
				SSL_get_cipher(ssl));
		}

		server_cert = SSL_get_peer_certificate(ssl);
		if(!server_cert) {
			perror("SSL_get_peer_certificate");
			return(-1);
		}
		X509_free(server_cert);

		/* TODO: Check server cert if changed! */
	}
#endif

	return(s);
}

/*
fd_getc() -- Read a character from an fd
*/
ssize_t fd_getc(int fd, void *c)
{
#ifdef HAVE_SSL
	if(use_tls == True) {
		return(SSL_read(ssl, c, 1));
	}
#endif
	return(read(fd, c, 1));
}

/*
fd_gets() -- Get characters from a fd instead of an fp
*/
char *fd_gets(char *buf, int size, int fd)
{
	int i = 0;
	char c;

	while((i < size) && (fd_getc(fd, &c) == 1)) {
		if(c == '\r');	/* Strip <CR> */
		else if(c == '\n') {
			break;
		}
		else {
			buf[i++] = c;
		}
	}
	buf[i] = 0;

	return(buf);
}

/*
smtp_read() -- Get a line and return the initial digit
*/
int smtp_read(int fd, char *response)
{
	do {
		if(fd_gets(response, BUF_SZ, fd) == NULL) {
			return(0);
		}
#ifdef MY_FEATURE
		dbprintf("response is %s\n", response);
		/* if mail server support CRAM-MD5, then set auth_method to CRAM-MD5 */
		if ((strstr(response, "250-AUTH") || strstr(response, "250 AUTH"))&& (strstr(response, "CRAM-MD5")))
		{
			dbprintf("support cram md5\n");
			cram_md5_flag = 1;
		}
		if ((strstr(response, "250-AUTH") || strstr(response, "250 AUTH")) && (strstr(response, "PLAIN")))
		{
			dbprintf("support auth plain\n");
			auth_plain_flag = 1;
		}
#endif

	}
	while(response[3] == '-');

	if(log_level > 0) {
		log_event(LOG_INFO, "%s\n", response);
	}

	if(minus_v) {
		(void)fprintf(stderr, "[<-] %s\n", response);
	}

	return(atoi(response) / 100);
}

/*
smtp_okay() -- Get a line and test the three-number string at the beginning
				If it starts with a 2, it's OK
*/
int smtp_okay(int fd, char *response)
{
	return((smtp_read(fd, response) == 2) ? 1 : 0);
}

/*
fd_puts() -- Write characters to fd
*/
ssize_t fd_puts(int fd, const void *buf, size_t count) 
{
#ifdef HAVE_SSL
	if(use_tls == True) { 
		return(SSL_write(ssl, buf, count));
	}
#endif
	return(write(fd, buf, count));
}

#ifdef MY_FEATURE
int send_to64frombits(int fd, const unsigned char *in, size_t inlen)
/* raw bytes in quasi-big-endian order to base 64 string (NUL-terminated) */
{
	char base64digits[] =
   		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char out_buf[80], *out;
	size_t out_len, total;
	unsigned long next_time, start_time;
	
	total = inlen;
	next_time = start_time = time(NULL);
	out_len = 0;
	out = out_buf;
    for (; inlen >= 3; inlen -= 3)
    {
		*out++ = base64digits[in[0] >> 2];
		*out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = base64digits[in[2] & 0x3f];
		in += 3;
		out_len+=4;
		if (out_len >= 72)	// divided by 4
		{
			out_buf[out_len++]='\r';
			out_buf[out_len++]='\n';
			out_buf[out_len]=0x00;

			if (fd_puts(fd, out_buf, out_len) < 0)
			{
				printf("SMTP: Write media data error\n");
				return -1;
			}

			out_len = 0;
			out = out_buf;
		}
		if (time(NULL) > next_time)
		{
			printf("SMTP: Xmt %d%%\n", ((total-inlen) * 100)/total);
			next_time = time(NULL) + 2;
		}
    }
    if (inlen >= 0)
    {
		unsigned char fragment;
    	
		*out++ = base64digits[in[0] >> 2];
		fragment = (in[0] << 4) & 0x30;
		if (inlen > 1)	fragment |= in[1] >> 4;
		*out++ = base64digits[fragment];
		*out++ = (inlen < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
		*out++ = '=';
		
		out_len+=4;
		out_buf[out_len++]='\r';
		out_buf[out_len++]='\n';
		out_buf[out_len]=0x00;

		if (fd_puts(fd, out_buf, out_len) < 0)
		{
			return -1;
		}    
    }
	dbprintf("SMTP: Finished to transmit data. (%d seconds)\n", (int)(time(NULL)-start_time));
    return 0;
}
#endif /* MY_FEATURE */

/*
smtp_write() -- A printf to an fd and append <CR/LF>
*/
void smtp_write(int fd, char *format, ...)
{
	char buf[(BUF_SZ + 1)];
	va_list ap;

	va_start(ap, format);
	if(vsnprintf(buf, (BUF_SZ - 2), format, ap) == -1) {
		die("smtp_write() -- vsnprintf() failed");
	}
	va_end(ap);

	if(log_level > 0) {
		log_event(LOG_INFO, "%s\n", buf);
	}

	if(minus_v) {
		(void)fprintf(stderr, "[->] %s\n", buf);
	}
	(void)strcat(buf, "\r\n");

	(void)fd_puts(fd, buf, strlen(buf));
}

/*
handler() -- A "normal" non-portable version of an alarm handler
			Alas, setting a flag and returning is not fully functional in
			BSD: system calls don't fail when reading from a ``slow'' device
			like a socket. So we longjump instead, which is erronious on
			a small number of machines and ill-defined in the language
*/
void handler(void)
{
	extern jmp_buf TimeoutJmpBuf;

	longjmp(TimeoutJmpBuf, (int)1);
}


#ifdef MY_FEATURE
int read_attachment(char * attchment, unsigned char * buf,int *length)
{
	int fd;
	struct stat file_state;
	if((fd =open(attchment,O_RDONLY)) == -1)
	{
		printf("read %s failed\n",attchment);
	    	return -1;
	}
	fstat(fd,&file_state);
	if(file_state.st_size > PICTURE_LEN)
	{
		close(fd);
		printf("attachment is too large\n");
		return -1;
	}
	*length = read(fd,buf,MAX_ATTACHMENT_LEN);
		 if(((*length) <= 0)||((*length) > PICTURE_LEN))
	{
		close(fd);
		printf("read attachment error\n");
		return -1;
	}
	close(fd);

	return 0;
}
#endif /* MY_FEATURE */

#ifdef MY_FEATURE

/*
ssmtp() -- send the message (exactly one) from stdin to the mailhub SMTP port
*/
int ssmtp(char *argv[])
{
	char buf[(BUF_SZ + 1)], *p;
#ifdef MD5AUTH
	char challenge[(BUF_SZ + 1)];
#endif
	struct passwd *pw;
	int  sock;
	uid_t uid;
	char temp_recipients[SMTP_BUF+1];

	uid = getuid();
	if((pw = getpwuid(uid)) == (struct passwd *)NULL) {
		myFree();
		exit(SSMTP_ERROR_CODE_INTERNAL);
	}
	get_arpadate(arpadate);

	if((p = strtok(pw->pw_gecos, ";,"))) {
		if((gecos = strdup(p)) == (char *)NULL) {
			myFree();
			exit(SSMTP_ERROR_CODE_INTERNAL);
		}
	}
	revaliases(pw);

	/* revaliases() may have defined this */
	if(uad == (char *)NULL) {
		uad = append_domain(pw->pw_name);
	}

#if 1
	/* With FromLineOverride=YES set, try to recover sane MAIL FROM address */
	uad = append_domain(uad);
#endif

	from = from_format(uad, override_from);

	/* Now to the delivery of the message */
	(void)signal(SIGALRM, (void(*)())handler);	/* Catch SIGALRM */
	(void)alarm((unsigned) MAXWAIT);			/* Set initial timer */
	if(setjmp(TimeoutJmpBuf) != 0) {
		myFree();
		exit(SSMTP_ERROR_CODE_INTERNAL);
	}

	if((sock = smtp_open(mailhost, port)) == -1) {
		dbprintf("Cannot open %s:%d", mailhost, port);
		myFree();
		exit(SSMTP_ERROR_CODE_NETWORK);
	}
	else if (use_starttls == False) /* no initial response after STARTTLS */
	{
		if(smtp_okay(sock, buf) == False)
		{
			(void)close(sock);
			dbprintf("Invalid response SMTP server");
			myFree();
			exit(SSMTP_ERROR_CODE_INTERNAL);
		}
	}
	/* If user supplied username and password, then try ELHO */
	/*if(auth_user) {
		smtp_write(sock, "EHLO %s", auth_user);
	}
	else {
		smtp_write(sock, "HELO %s", hostname);
	}*/

	smtp_write(sock, "EHLO %s", hostname);

	(void)alarm((unsigned) MEDWAIT);

	if(smtp_okay(sock, buf) == False) {
		(void)close(sock);
		dbprintf("HELO failed %s (%s)", buf, hostname);
		myFree();
		exit(SSMTP_ERROR_CODE_USERNAME);
	}

	dbprintf("after EHLO, buf is %s\n", buf);

	/* Try to log in if username was supplied */
	if(auth_user) {
#ifndef MY_FEATURE
		if(auth_pass == (char *)NULL) {
			auth_pass = strdup("");
		}
#endif	/* end of MY_FEA_TURE */

		int auth_success = 0;

		/* try cram_md5 login */
		if (!auth_success && 1 == cram_md5_flag)
		{
			smtp_write(sock, "AUTH CRAM-MD5");
			(void)alarm((unsigned) MEDWAIT);

			dbprintf("cram-md5\n");
			if(3 != smtp_read(sock, buf)) 
			{
				printf("cram-md5 failed, buf is %s\n", buf);
				auth_success = 0;
			}
			else
			{
				strncpy(challenge, strchr(buf,' ') + 1, sizeof(challenge));
				memset(buf, 0, sizeof(buf));
				crammd5(challenge, auth_user, auth_pass, buf);
				auth_success = 1;
			}
		}

		/* try plain login */
		if (!auth_success && 1 == auth_plain_flag)
		{
			smtp_write(sock, "AUTH PLAIN");
			(void)alarm((unsigned) MEDWAIT);

			dbprintf("auth plain\n");
			if(3 != smtp_read(sock, buf)) 
			{
				printf("auth plain failed, buf is %s\n", buf);
				auth_success = 0;
			}
			else
			{
				char tmp[BUF_SZ+1];
				memset(tmp, '\0', sizeof(tmp));
				strncpy(&tmp[1],auth_user, strlen(auth_user));
				strncpy(&tmp[strlen(auth_user)+2],auth_pass, strlen(auth_pass));
				to64frombits((unsigned char *)buf, (unsigned char *)tmp, strlen(auth_pass)+strlen(auth_user)+2);
				auth_success = 1;
			}
		}

		/* try auth login */
		if (!auth_success)
		{
			memset(buf, 0, sizeof(buf));
			to64frombits((unsigned char*)buf, (unsigned char *)auth_user, strlen(auth_user));
			smtp_write(sock, "AUTH LOGIN %s", buf);

			dbprintf("auth login\n");

			(void)alarm((unsigned) MEDWAIT);
			if(3 != smtp_read(sock, buf)) 
			{
				(void)close(sock);
				dbprintf("Server didn't accept AUTH LOGIN (%s)", buf);
				myFree();
				exit(SSMTP_ERROR_CODE_SERVER);
			}
			memset(buf, 0, sizeof(buf));
			to64frombits((unsigned char *)buf, (unsigned char *)auth_pass, strlen(auth_pass));
		}

		/* send username and password */
		smtp_write(sock, "%s", buf);
		(void)alarm((unsigned) MEDWAIT);

		if(False == smtp_okay(sock, buf)) 
		{
			(void)close(sock);
			dbprintf("Authorization failed (%s)", buf);
			myFree();
			exit(SSMTP_ERROR_CODE_PASSWORD);
		}
	}

	dbprintf("haha, login in\n");

	/* Send "MAIL FROM:" line */
	smtp_write(sock, "MAIL FROM:<%s>", sender);

	(void)alarm((unsigned) MEDWAIT);

	if(smtp_okay(sock, buf) == 0) {
		(void)close(sock);
		dbprintf("Authorization failed (%s)", buf);
		myFree();
		exit(SSMTP_ERROR_CODE_SENDER);
	}
	dbprintf("before RTCP TO\n");

    /* Send all the To: adresses */
    strncpy(temp_recipients, recipients, SMTP_BUF);
    temp_recipients[SMTP_BUF] = '\0';
    char mail_to_result[MAIL_TO_MAX + 1];
    int count=0;
    memset(mail_to_result, '\0', sizeof(mail_to_result));
    strncpy(mail_to_result,SSMTP_MAIL_TO_RESULT_DEFAULT, sizeof(mail_to_result)-1);
#if 0
    p=strtok(recipients,";");
    while(p)
    {
    		/* MAIL_TO_MAX receivers at most */
    		if (count >= MAIL_TO_MAX)
    		{
    			break;
    		}
			
		smtp_write(sock, "RCPT TO:<%s>", p);
		dbprintf("count is %d RCPT TO:<%s>\n",count, p);

		/* if one receiver failed, ignore him */
		if(smtp_okay(sock, buf) == False)
	     	{
		       dbprintf("RCPT TO:<%s> (%s)\n", p, buf);
			mail_to_result[count] = '1';
	     	 }
		 else
		 {
			mail_to_result[count] = '0';
		 }
		  p=strtok(NULL,";");
		  count++;
    }
#endif
	/* add ";" at last */
	strncat(recipients, ";", 1);
	char *tmp =  recipients;
	p = strchr(tmp, ';');
	int send_mail_flag = 0;
	while (p)
	{
		/* MAIL_TO_MAX receivers at most */
    		if (count >= MAIL_TO_MAX)
    		{
    			dbprintf("count is %d\n", count);
    			break;
    		}
		if (0 == (p - tmp))
		{
			mail_to_result[count] = '0';
			tmp++;
			dbprintf("p - tmp is 0 count is %d\n", count);
		}
		else
		{
			*p = '\0';
			smtp_write(sock, "RCPT TO:<%s>", tmp);
			dbprintf("count is %d RCPT TO:<%s>\n",count, tmp);

			/* if one receiver failed, ignore him */
			if(smtp_okay(sock, buf) == False)
		     	{
			       dbprintf("RCPT TO:<%s> (%s)\n", tmp, buf);
				mail_to_result[count] = '1';
		     	 }
			 else
			 {
				mail_to_result[count] = '0';
				send_mail_flag = 1;
			 }
			 p++;
			 tmp = p;
		}
		 p = strchr(tmp, ';');
		count++;
	}

	/* all reveiver is error */
	if (0 == strcmp("1111", mail_to_result) || 0 == send_mail_flag)
	{
		dbprintf("all receiver is error\n");
		exit(SSMTP_ERROR_CODE_RECEIVER);
	}

	/* if it is test, then save result in SSMTP_TEST_FILE_RESULT */
	if (isTest)
	{
    		WriteStringToFile(SSMTP_TEST_FILE_RESULT,mail_to_result, sizeof(mail_to_result));
	}

	/* Send DATA */
	smtp_write(sock, "DATA");(void)alarm((unsigned) MEDWAIT);

	if(smtp_read(sock, buf) != 3) {
		(void)close(sock);
		/* Oops, we were expecting "354 send your data" */
		dbprintf("error %s", buf);
		myFree();
		exit(SSMTP_ERROR_CODE_SERVER);
	}

	dbprintf("begin to send data\n");


#ifdef HASTO_OPTION
	if(have_to == False) {
		smtp_write(sock, "To: postmaster");
	}
#endif

	if (NULL != text_body)
	{
		to64frombits((unsigned char *)buf, (unsigned char *)text_body,strlen(text_body));
	}

	if (NULL != isTest)
	{
		smtp_write(sock,
				"From: %s\r\n"
				"To: %s\r\n"
				"Subject: %s\r\n"
				"Date: %s\r\n"
				"MIME-Version: 1.0\r\n"
				"Content-Type: multipart/mixed;\r\n"
				"\tboundary=\"ipcam_stmp\"\r\n\r\n"
				"--ipcam_stmp\r\n"                // boundary
				"Content-Type: text/plain;\r\n"
				 "Content-Transfer-Encoding: base64\r\n\r\n"
				"%s\r\n\r\n",                        //content
				sender,
				temp_recipients,
				subject,
				arpadate,
				buf
		);

	}
	else
	{
		smtp_write(sock,
				"From: %s\r\n"
				"To: %s\r\n"
				"Subject: %s\r\n"
				"Date: %s\r\n"
				"MIME-Version: 1.0\r\n"
				"Content-Type: multipart/mixed;\r\n"
				"\tboundary=\"ipcam_stmp\"\r\n\r\n"
				"--ipcam_stmp\r\n"                // boundary
				"Content-Type: text/plain;\r\n"
				 "Content-Transfer-Encoding: base64\r\n\r\n"
				"%s\r\n\r\n",                        //content
				sender,
				temp_recipients,
				subject,
				arpadate,
				buf
		);
		
		int flag=0;
		char * split;
		 p=strtok(attachment_path,";");
		while(p)
		{
			split = strrchr(p,'/');
			if (split != NULL)
			{
			   	sprintf(attachment_name,split+1);
			}
			else
			{
			   	sprintf(attachment_name,p);
			}

			memset(media_data, '\0', sizeof(media_data));
			
			if ( 0 == read_attachment(p,media_data,&attachment_length))
			{
				smtp_write(sock,
							 "--ipcam_stmp\r\n"			    // boundary
							   "Content-Type: video/x-msvideo;\r\n"           
							   "Content-Transfer-Encoding: base64\r\n"
							   "Content-Disposition: attachment;\r\n"
							   "\tfilename=\"%s\"\r\n\r\n",    // attach_file_name
							   attachment_name);
				   send_to64frombits(sock, media_data, attachment_length);
				   flag = 1;
			}
			p=strtok(NULL,";");
		}

		/*if send attachments not success, cancel this mail */
		if (!flag)
		{
			smtp_write(sock,"RESET");
			 (void)close(sock);
			 myFree();
			 exit(SSMTP_ERROR_CODE_NO_ATTACHMENT);
		}
	}
	/* End of body */

	smtp_write(sock, ".");
	(void)alarm((unsigned) MAXWAIT);

	if(smtp_okay(sock, buf) == 0) {
		(void)close(sock);
		dbprintf("error %s", buf);
		myFree();
		exit(SSMTP_ERROR_CODE_SERVER);
	}


	/* Close conection */
	(void)signal(SIGALRM, SIG_IGN);

	smtp_write(sock, "QUIT");
	(void)smtp_okay(sock, buf);
	(void)close(sock);

	myFree();
	dbprintf("ssmtp end\n");

	return(SSMTP_ERROR_CODE_SUCCESS);
}
#endif


#ifndef MY_FEATURE
/*
ssmtp() -- send the message (exactly one) from stdin to the mailhub SMTP port
*/
int ssmtp(char *argv[])
{
	char buf[(BUF_SZ + 1)], *p, *q;
#ifdef MD5AUTH
	char challenge[(BUF_SZ + 1)];
#endif
	struct passwd *pw;
	int i, sock;
	uid_t uid;

	uid = getuid();
	if((pw = getpwuid(uid)) == (struct passwd *)NULL) {
		die("Could not find password entry for UID %d", uid);
	}
	get_arpadate(arpadate);

	if(read_config() == False) {
		log_event(LOG_INFO, "%s/ssmtp.conf not found", SSMTPCONFDIR);
	}

	if((p = strtok(pw->pw_gecos, ";,"))) {
		if((gecos = strdup(p)) == (char *)NULL) {
			die("ssmtp() -- strdup() failed");
		}
	}
	revaliases(pw);

	/* revaliases() may have defined this */
	if(uad == (char *)NULL) {
		uad = append_domain(pw->pw_name);
	}

	ht = &headers;
	rt = &rcpt_list;

	header_parse(stdin);

#if 1
	/* With FromLineOverride=YES set, try to recover sane MAIL FROM address */
	uad = append_domain(uad);
#endif

	from = from_format(uad, override_from);

	/* Now to the delivery of the message */
	(void)signal(SIGALRM, (void(*)())handler);	/* Catch SIGALRM */
	(void)alarm((unsigned) MAXWAIT);			/* Set initial timer */
	if(setjmp(TimeoutJmpBuf) != 0) {
		/* Then the timer has gone off and we bail out */
		die("Connection lost in middle of processing");
	}

	if((sock = smtp_open(mailhost, port)) == -1) {
		die("Cannot open %s:%d", mailhost, port);
	}
	else if (use_starttls == False) /* no initial response after STARTTLS */
	{
		if(smtp_okay(sock, buf) == False)
			die("Invalid response SMTP server");
	}

	/* If user supplied username and password, then try ELHO */
	if(auth_user) {
		smtp_write(sock, "EHLO %s", hostname);
	}
	else {
		smtp_write(sock, "HELO %s", hostname);
	}
	(void)alarm((unsigned) MEDWAIT);

	if(smtp_okay(sock, buf) == False) {
		die("%s (%s)", buf, hostname);
	}

	/* Try to log in if username was supplied */
	if(auth_user) {
#ifdef MD5AUTH
		if(auth_pass == (char *)NULL) {
			auth_pass = strdup("");
		}

		if(strcasecmp(auth_method, "cram-md5") == 0) {
			smtp_write(sock, "AUTH CRAM-MD5");
			(void)alarm((unsigned) MEDWAIT);

			if(smtp_read(sock, buf) != 3) {
				die("Server rejected AUTH CRAM-MD5 (%s)", buf);
			}
			strncpy(challenge, strchr(buf,' ') + 1, sizeof(challenge));

			memset(buf, 0, sizeof(buf));
			crammd5(challenge, auth_user, auth_pass, buf);
		}
		else {
#endif
		memset(buf, 0, sizeof(buf));
		to64frombits(buf, auth_user, strlen(auth_user));
		smtp_write(sock, "AUTH LOGIN %s", buf);

		(void)alarm((unsigned) MEDWAIT);
		if(smtp_read(sock, buf) != 3) {
			die("Server didn't accept AUTH LOGIN (%s)", buf);
		}
		memset(buf, 0, sizeof(buf));

		to64frombits(buf, auth_pass, strlen(auth_pass));
#ifdef MD5AUTH
		}
#endif
		smtp_write(sock, "%s", buf);
		(void)alarm((unsigned) MEDWAIT);

		if(smtp_okay(sock, buf) == False) {
			die("Authorization failed (%s)", buf);
		}
	}

	/* Send "MAIL FROM:" line */
	smtp_write(sock, "MAIL FROM:<%s>", uad);

	(void)alarm((unsigned) MEDWAIT);

	if(smtp_okay(sock, buf) == 0) {
		die("%s", buf);
	}

	/* Send all the To: adresses */
	/* Either we're using the -t option, or we're using the arguments */
	if(minus_t) {
		if(rcpt_list.next == (rcpt_t *)NULL) {
			die("No recipients specified although -t option used");
		}
		rt = &rcpt_list;

		while(rt->next) {
			p = rcpt_remap(rt->string);
			smtp_write(sock, "RCPT TO:<%s>", p);

			(void)alarm((unsigned)MEDWAIT);

			if(smtp_okay(sock, buf) == 0) {
				die("RCPT TO:<%s> (%s)", p, buf);
			}

			rt = rt->next;
		}
	}
	else {
		for(i = 1; (argv[i] != NULL); i++) {
			p = strtok(argv[i], ",");
			while(p) {
				/* RFC822 Address -> "foo@bar" */
				q = rcpt_remap(addr_parse(p));
				smtp_write(sock, "RCPT TO:<%s>", q);

				(void)alarm((unsigned) MEDWAIT);

				if(smtp_okay(sock, buf) == 0) {
					die("RCPT TO:<%s> (%s)", q, buf);
				}

				p = strtok(NULL, ",");
			}
		}
	}

	/* Send DATA */
	smtp_write(sock, "DATA");
	(void)alarm((unsigned) MEDWAIT);

	if(smtp_read(sock, buf) != 3) {
		/* Oops, we were expecting "354 send your data" */
		die("%s", buf);
	}

	smtp_write(sock,
		"Received: by %s (sSMTP sendmail emulation); %s", hostname, arpadate);

	if(have_from == False) {
		smtp_write(sock, "From: %s", from);
	}

	if(have_date == False) {
		smtp_write(sock, "Date: %s", arpadate);
	}

#ifdef HASTO_OPTION
	if(have_to == False) {
		smtp_write(sock, "To: postmaster");
	}
#endif

	ht = &headers;
	while(ht->next) {
		smtp_write(sock, "%s", ht->string);
		ht = ht->next;
	}

	(void)alarm((unsigned) MEDWAIT);

	/* End of headers, start body */
	smtp_write(sock, "");

	while(fgets(buf, sizeof(buf), stdin)) {
		/* Trim off \n, double leading .'s */
		standardise(buf);

		smtp_write(sock, "%s", buf);

		(void)alarm((unsigned) MEDWAIT);
	}
	/* End of body */

	smtp_write(sock, ".");
	(void)alarm((unsigned) MAXWAIT);

	if(smtp_okay(sock, buf) == 0) {
		die("%s", buf);
	}

	/* Close conection */
	(void)signal(SIGALRM, SIG_IGN);

	smtp_write(sock, "QUIT");
	(void)smtp_okay(sock, buf);
	(void)close(sock);

	log_event(LOG_INFO, "Sent mail for %s (%s)", from_strip(uad), buf);

	return(0);
}
#endif

/*
paq() - Write error message and exit
*/
void paq(char *format, ...)
{
	va_list ap;   

	va_start(ap, format);
	(void)vfprintf(stderr, format, ap);
	va_end(ap);

	exit(0);
}


#ifndef MY_FEATURE
/*
parse_options() -- Pull the options out of the command-line
	Process them (special-case calls to mailq, etc) and return the rest
*/
char **parse_options(int argc, char *argv[])
{
	static char Version[] = VERSION;
	static char *new_argv[MAXARGS];
	int i, j, add, new_argc;

	new_argv[0] = argv[0];
	new_argc = 1;

	if(strcmp(prog, "mailq") == 0) {
		/* Someone wants to know the queue state... */
		paq("mailq: Mail queue is empty\n");
	}
	else if(strcmp(prog, "newaliases") == 0) {
		/* Someone wanted to rebuild aliases */
		paq("newaliases: Aliases are not used in sSMTP\n");
	}

	i = 1;
	while(i < argc) {
		if(argv[i][0] != '-') {
			new_argv[new_argc++] = argv[i++];
			continue;
		}
		j = 0;

		add = 1;
		while(argv[i][++j] != 0) {
			switch(argv[i][j]) {
#ifdef INET6
			case '6':
				p_family = PF_INET6;
				continue;

			case '4':
				p_family = PF_INET;
			continue;
#endif

			case 'a':
				switch(argv[i][++j]) {
				case 'u':
					if((!argv[i][(j + 1)])
						&& argv[(i + 1)]) {
						auth_user = strdup(argv[i+1]);
						if(auth_user == (char *)NULL) {
							die("parse_options() -- strdup() failed");
						}
						add++;
					}
					else {
						auth_user = strdup(argv[i]+j+1);
						if(auth_user == (char *)NULL) {
							die("parse_options() -- strdup() failed");
						}
					}
					goto exit;

				case 'p':
					if((!argv[i][(j + 1)])
						&& argv[(i + 1)]) {
						auth_pass = strdup(argv[i+1]);
						if(auth_pass == (char *)NULL) {
							die("parse_options() -- strdup() failed");
						}
						add++;
					}
					else {
						auth_pass = strdup(argv[i]+j+1);
						if(auth_pass == (char *)NULL) {
							die("parse_options() -- strdup() failed");
						}
					}
					goto exit;

/*
#ifdef MD5AUTH
*/
				case 'm':
					if(!argv[i][j+1]) { 
						auth_method = strdup(argv[i+1]);
						add++;
					}
					else {
						auth_method = strdup(argv[i]+j+1);
					}
				}
				goto exit;
/*
#endif
*/

			case 'b':
				switch(argv[i][++j]) {

				case 'a':	/* ARPANET mode */
						paq("-ba is not supported by sSMTP\n");
				case 'd':	/* Run as a daemon */
						paq("-bd is not supported by sSMTP\n");
				case 'i':	/* Initialise aliases */
						paq("%s: Aliases are not used in sSMTP\n", prog);
				case 'm':	/* Default addr processing */
						continue;

				case 'p':	/* Print mailqueue */
						paq("%s: Mail queue is empty\n", prog);
				case 's':	/* Read SMTP from stdin */
						paq("-bs is not supported by sSMTP\n");
				case 't':	/* Test mode */
						paq("-bt is meaningless to sSMTP\n");
				case 'v':	/* Verify names only */
						paq("-bv is meaningless to sSMTP\n");
				case 'z':	/* Create freeze file */
						paq("-bz is meaningless to sSMTP\n");
				}

			/* Configfile name */
			case 'C':
				goto exit;

			/* Debug */
			case 'd':
				log_level = 1;
				/* Almost the same thing... */
				minus_v = True;

				continue;

			/* Insecure channel, don't trust userid */
			case 'E':
					continue;

			case 'R':
				/* Amount of the message to be returned */
				if(!argv[i][j+1]) {
					add++;
					goto exit;
				}
				else {
					/* Process queue for recipient */
					continue;
				}

			/* Fullname of sender */
			case 'F':
				if((!argv[i][(j + 1)]) && argv[(i + 1)]) {
					minus_F = strdup(argv[(i + 1)]);
					if(minus_F == (char *)NULL) {
						die("parse_options() -- strdup() failed");
					}
					add++;
				}
				else {
					minus_F = strdup(argv[i]+j+1);
					if(minus_F == (char *)NULL) {
						die("parse_options() -- strdup() failed");
					}
				}
				goto exit;

			/* Set from/sender address */
			case 'f':
			/* Obsolete -f flag */
			case 'r':
				if((!argv[i][(j + 1)]) && argv[(i + 1)]) {
					minus_f = strdup(argv[(i + 1)]);
					if(minus_f == (char *)NULL) {
						die("parse_options() -- strdup() failed");
					}
					add++;
				}
				else {
					minus_f = strdup(argv[i]+j+1);
					if(minus_f == (char *)NULL) {
						die("parse_options() -- strdup() failed");
					}
				}
				goto exit;

			/* Set hopcount */
			case 'h':
				continue;

			/* Ignore originator in adress list */
			case 'm':
				continue;

			/* Use specified message-id */
			case 'M':
				goto exit;

			/* DSN options */
			case 'N':
				add++;
				goto exit;

			/* No aliasing */
			case 'n':
				continue;

			case 'o':
				switch(argv[i][++j]) {

				/* Alternate aliases file */
				case 'A':
					goto exit;

				/* Delay connections */
				case 'c':
					continue;

				/* Run newaliases if required */
				case 'D':
					paq("%s: Aliases are not used in sSMTP\n", prog);

				/* Deliver now, in background or queue */
				/* This may warrant a diagnostic for b or q */
				case 'd':
						continue;

				/* Errors: mail, write or none */
				case 'e':
					j++;
					continue;

				/* Set tempfile mode */
				case 'F':
					goto exit;

				/* Save ``From ' lines */
				case 'f':
					continue;

				/* Set group id */
				case 'g':
					goto exit;

				/* Helpfile name */
				case 'H':
					continue;

				/* DATA ends at EOF, not \n.\n */
				case 'i':
					continue;

				/* Log level */
				case 'L':
					goto exit;

				/* Send to me if in the list */
				case 'm':
					continue;

				/* Old headers, spaces between adresses */
				case 'o':
					paq("-oo is not supported by sSMTP\n");

				/* Queue dir */
				case 'Q':
					goto exit;

				/* Read timeout */
				case 'r':
					goto exit;

				/* Always init the queue */
				case 's':
					continue;

				/* Stats file */
				case 'S':
					goto exit;

				/* Queue timeout */
				case 'T':
					goto exit;

				/* Set timezone */
				case 't':
					goto exit;

				/* Set uid */
				case 'u':
					goto exit;

				/* Set verbose flag */
				case 'v':
					minus_v = True;
					continue;
				}
				break;

			/* Process the queue [at time] */
			case 'q':
					paq("%s: Mail queue is empty\n", prog);

			/* Read message's To/Cc/Bcc lines */
			case 't':
				minus_t = True;
				continue;

			/* minus_v (ditto -ov) */
			case 'v':
				minus_v = True;
				break;

			/* Say version and quit */
			/* Similar as die, but no logging */
			case 'V':
				paq("sSMTP %s (Not sendmail at all)\n", Version);
			}
		}

		exit:
		i += add;
	}
	new_argv[new_argc] = NULL;

	if(new_argc <= 1 && !minus_t) {
		paq("%s: No recipients supplied - mail will not be sent\n", prog);
	}

	if(new_argc > 1 && minus_t) {
		paq("%s: recipients with -t option not supported\n", prog);
	}

	return(&new_argv[0]);
}
#endif /* MY_FEATURE */

#ifdef MY_FEATURE

void help()
{
	printf("Usage: %s [-a Attachment path] [-c content] [-f Configure file path] [-s subject]\n",prog);
	exit(1);
}


static void sigKillHandler()
{
	dbprintf("smtp catch kill, exit\n");

	/* timeout and to be killed, we think sender mail not success because network error */
	exit(SSMTP_ERROR_CODE_NETWORK);
}

static void process_sigpipe()
{
	dbprintf("smtp catch sigpipe,exit\n");
	exit(SSMTP_ERROR_CODE_INTERNAL);
}

#endif /* MY_FEATURE */



/*
main() -- make the program behave like sendmail, then call ssmtp
*/
int main(int argc, char **argv)
{	
	char **new_argv = NULL;
#ifdef MY_FEATURE
	int opt;
#endif /* MY_FEATURE */

	dbprintf("ssmtp begin\n");

	/* Try to be bulletproof :-) */
	(void)signal(SIGHUP, SIG_IGN);
	//(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGTTIN, SIG_IGN);
	(void)signal(SIGTTOU, SIG_IGN);

#ifdef MY_FEATURE
	/* add by chm */
	signal(SIGPIPE, process_sigpipe);
	signal(SIGTERM,sigKillHandler);
	signal(SIGKILL,sigKillHandler);
	signal(SIGINT,sigKillHandler);
#endif

	/* Set the globals */
	prog = basename(argv[0]);


	/*if(gethostname(hostname, MAXHOSTNAMELEN) == -1) {
		exit(SSMTP_ERROR_CODE_NETWORK);
	}*/

#ifdef MY_FEATURE
	while((opt = getopt(argc,argv,"a:c:s:f:t:"))!= -1)
	{
		switch (opt)
		{
		case 'a':
			attachment_path = optarg;
			break;
		case 'c':
			text_body = optarg;
			break;
		case 'f':
			config_file_path = optarg;
			break;
		case 's':
			subject = optarg;
			break;
		case 't':
			isTest = optarg;
			break;
		default:
			help();
			break;
		}
	}

	my_read_config();

#else /* MY_FEATURE */
    new_argv = parse_options(argc, argv);
#endif /* MY_FEATURE */
	exit(ssmtp(new_argv));
}

