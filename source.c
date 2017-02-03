/*
Copyright (C) 1996-1997 Id Software, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See the included (GNU.txt) GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/


//connection notes
//The connection is like http.
//The stream starts with a small header.
//The header is a list of 'key: value' pairs, seperated by new lines.
//The header ends with a totally blank line.
//to record an mvd from telnet or somesuch, you would use:
//"QTV\nRAW: 1\n\n"

//VERSION: a list of the different qtv protocols supported. Multiple versions can be specified. The first is assumed to be the prefered version.
//RAW: if non-zero, send only a raw mvd with no additional markup anywhere (for telnet use). Doesn't work with challenge-based auth, so will only be accepted when proxy passwords are not required.
//AUTH: specifies an auth method, the exact specs varies based on the method
//		PLAIN: the password is sent as a PASSWORD line
//		MD4: the server responds with an "AUTH: MD4\n" line as well as a "CHALLENGE: somerandomchallengestring\n" line, the client sends a new 'initial' request with CHALLENGE: MD4\nRESPONSE: hexbasedmd4checksumhere\n"
//		CCITT: same as md4, but using the CRC stuff common to all quake engines.
//		if the supported/allowed auth methods don't match, the connection is silently dropped.
//SOURCE: which stream to play from, DEFAULT is special. Without qualifiers, it's assumed to be a tcp address.
//COMPRESSION: Suggests a compression method (multiple are allowed). You'll get a COMPRESSION response, and compression will begin with the binary data.
//SOURCELIST: Asks for a list of active sources from the proxy.
//DEMOLIST:	Asks for a list of available mvd demos.

//Response:
//if using RAW, there will be no header or anything
//Otherwise you'll get a QTVSV %f response (%f being the protocol version being used)
//same structure, terminated by a \n
//AUTH: Server requires auth before proceeding. If you don't support the method the server says, then, urm, the server shouldn't have suggested it.
//CHALLENGE: used with auth
//COMPRESSION: Method of compression used. Compression begins with the raw data after the connection process.
//ASOURCE: names a source
//ADEMO: gives a demo file name



#include "qtv.h"

#ifndef _WIN32
#include <signal.h>
#endif

cvar_t maxservers				= {"maxservers", "100"};
cvar_t upstream_timeout			= {"upstream_timeout", "60"};
cvar_t parse_delay				= {"parse_delay", "7"};
cvar_t qtv_reconnect_delay		= {"qtv_reconnect_delay", "30"};
cvar_t qtv_max_reconnect_delay	= {"qtv_max_reconnect_delay", "86400"}; // 24 hours.
cvar_t qtv_backoff				= {"qtv_backoff", "1"};

#define BUFFERTIME 10	// secords for artificial delay, so we can buffer things properly.

// set source to state SRC_BAD, opened sources must be freed/closed before
// thought direct call to this function need only in QTV_NewServerConnection() and QTV_Connect() and sure in close_source()
void init_source(sv_t *qtv)
{
	memset(&(qtv->src), 0, sizeof(qtv->src));

	qtv->src.s 		= INVALID_SOCKET; // sigh, we need it
	qtv->src.type	= SRC_BAD;
}

// close/free opened resources and set source to state SRC_BAD
void close_source(sv_t *qtv, const char *where)
{
    switch (qtv->src.type)
	{
		case SRC_DEMO:
		case SRC_TCP:
		case SRC_BAD:
			break; // its known sources

		default:
			Sys_Printf("%s: Error: %s: unknown source type %d\n", qtv->server, (where ? where : "unknown"), qtv->src.type);
    }

	if (qtv->src.f)
		fclose(qtv->src.f);

	if (qtv->src.s != INVALID_SOCKET)
		closesocket(qtv->src.s);

	init_source(qtv); // set source to state SRC_BAD, its safe call it since we free all resorces like SOCKET and FILE
}

void Net_SendQTVConnectionRequest(sv_t *qtv, char *authmethod, char *challenge)
{
	qtv->qstate = qs_parsingQTVheader;

	Net_UpstreamPrintf(qtv, "QTV\nVERSION: 1\n");

	if (qtv->ServerQuery)
	{
		Net_UpstreamPrintf(qtv, qtv->ServerQuery == 2 ? "DEMOLIST\n" : "SOURCELIST\n");
	}
	else
	{
		char *at;
		char hash[512];

		at = strchrrev(qtv->server, '@');

		if (at)
		{
			char *str;

			*at = '\0'; // Here we modifying qtv->server, OUCH

			if (strncmp(qtv->server, "tcp:", 4))
			{
				str = qtv->server;
			}
			else
			{
			 	if ((str = strchr(qtv->server, ':')))
					str++;
			}

			// hm, str may be NULL, so we send "SOURCE: \n", is this correct?
			Net_UpstreamPrintf(qtv, "SOURCE: %s\n", str ? str : "");

			*at = '@'; // restore qtv->server
		}
		else
		{
			Net_UpstreamPrintf(qtv, "RECEIVE\n");
		}

		// send hostname as userinfo
		{
			extern cvar_t address;

			char userinfo[1024] = {0};
			char temp[20] = { 0 };

			snprintf (temp, sizeof (temp), "%u", qtv->streamid);

			Info_SetValueForStarKey(userinfo, "name", hostname.string, sizeof(userinfo));
			if (address.string[0])
			{
				Info_SetValueForStarKey (userinfo, "address", address.string, sizeof (userinfo));
				Info_SetValueForStarKey (userinfo, "streamid", temp, sizeof (userinfo));
			}

			if (userinfo[0])
				Net_UpstreamPrintf(qtv, "USERINFO: \"%s\"\n", userinfo);
		}

// qqshka: we do not use RAW at all, so do not bother
//		if (!qtv->ParsingQTVheader)
//		{
//			Net_UpstreamPrintf(qtv, "RAW: 1\n");
//		}
//		else
		{
			if (authmethod)
			{
				if (!strcmp(authmethod, "PLAIN"))
				{
					Net_UpstreamPrintf(qtv, "AUTH: PLAIN\nPASSWORD: \"%s\"\n", qtv->ConnectPassword);
				}
				else if (challenge && strlen(challenge)>=32 && !strcmp(authmethod, "CCITT"))
				{
					unsigned short crcvalue;

					snprintf(hash, sizeof(hash), "%s%s", challenge, qtv->ConnectPassword);
					crcvalue = QCRC_Block((unsigned char *)hash, strlen(hash));
					snprintf(hash, sizeof(hash), "0x%X", (unsigned int)QCRC_Value(crcvalue));

					Net_UpstreamPrintf(qtv, "AUTH: CCITT\nPASSWORD: \"%s\"\n", hash);
				}
				else if (challenge && strlen(challenge)>=8 && !strcmp(authmethod, "MD4"))
				{
					unsigned int md4sum[4];

					snprintf(hash, sizeof(hash), "%s%s", challenge, qtv->ConnectPassword);
					Com_BlockFullChecksum (hash, strlen(hash), (unsigned char*)md4sum);
					snprintf(hash, sizeof(hash), "%X%X%X%X", md4sum[0], md4sum[1], md4sum[2], md4sum[3]);

					Net_UpstreamPrintf(qtv, "AUTH: MD4\nPASSWORD: \"%s\"\n", hash);
				}
				else if (!strcmp(authmethod, "NONE"))
				{
					Net_UpstreamPrintf(qtv, "AUTH: NONE\nPASSWORD: \n");
				}
				else
				{
					qtv->drop = true;
					qtv->UpstreamBufferSize = 0;
					Sys_Printf("%s: Auth method %s was not usable\n", qtv->server, authmethod);
					return;
				}
			}
			else
			{
				Net_UpstreamPrintf(qtv, "AUTH: MD4\nAUTH: CCITT\nAUTH: PLAIN\nAUTH: NONE\n");
			}
		}
	}

	Net_UpstreamPrintf(qtv, "\n");
}

qbool Net_ConnectToTCPServer(sv_t *qtv, char *ip)
{
	int err;
	struct sockaddr_in from;
	unsigned long nonblocking = true;

	if (qtv->src.type != SRC_TCP) 
	{
		Sys_Printf("%s: Source set to wrong type %d, need %d = SRC_TCP\n", qtv->server, qtv->src.type, SRC_TCP);
		return false;
	}

	if (qtv->src.s != INVALID_SOCKET)
	{
		Sys_Printf("%s: Forcing close of source socket, bug\n", qtv->server);
		close_source(qtv, "Net_ConnectToTCPServer");
		qtv->src.type = SRC_TCP; // need SRC_TCP type
	}

	if (!Net_StringToAddr(&qtv->ServerAddress, ip, 27500))
	{
		Sys_Printf("%s: Unable to resolve %s\n", qtv->server, ip);
		return false;
	}

	qtv->src.s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (qtv->src.s == INVALID_SOCKET)
		return false;

	memset(&from, 0, sizeof(from));
	from.sin_family = qtv->ServerAddress.sin_family;
	if (bind(qtv->src.s, (struct sockaddr *)&from, sizeof(from)) == -1)
		return false;

	if (ioctlsocket (qtv->src.s, FIONBIO, &nonblocking) == -1)
		return false;

	if (!TCP_Set_KEEPALIVE(qtv->src.s))
		return false;

	if (connect(qtv->src.s, (struct sockaddr *)&qtv->ServerAddress, sizeof(qtv->ServerAddress)) == INVALID_SOCKET)
	{
		err = qerrno;
		
		// BSD sockets are meant to return EINPROGRESS, but some winsock drivers use EWOULDBLOCK instead. *sigh*...
		if (err != EINPROGRESS && err != EAGAIN && err != EWOULDBLOCK)	
			return false;
	}

	// Read the notes at the start of this file for what these text strings mean.
	Net_SendQTVConnectionRequest(qtv, NULL, NULL);
	return true;
}

qbool OpenDemoFile(sv_t *qtv, char *demo)
{
	char fullpath[1024];
	int size;

	snprintf(fullpath, sizeof(fullpath), "%s/%s", DEMO_DIR, demo);

	if (qtv->src.type != SRC_DEMO)
	{
		Sys_Printf("%s: Source set to wrong type %d, need %d = SRC_DEMO\n", qtv->server, qtv->src.type, SRC_DEMO);
		return false;
	}

	if (qtv->src.f)
	{
		Sys_Printf("%s: Forcing close of source file, bug\n", qtv->server);
		close_source(qtv, "OpenDemoFile");
		qtv->src.type = SRC_DEMO; // Need SRC_DEMO type.
	}

	if(stricmp(".mvd", FS_FileExtension(fullpath))) // .mvd demos only
		return false;

	if ((qtv->src.f = FS_OpenFile(NULL, fullpath, &size)))
	{
		qtv->src.f_size = size;

		if (qtv->src.f_size > 0)
		{
			// In demo case we don't require parsing the QTV header, so set this state.
			qtv->qstate = qs_parsingconnection; 
			return true;
		}	
	}

	return false;
}

// Resets frame values.
void QTV_SetupFrames(sv_t *qtv)
{
	int i;

	memset(qtv->frame, 0, sizeof(qtv->frame));

	for (i = 0; i < MAX_ENTITY_FRAMES; i++)
		qtv->frame[i].maxents = MAX_DEMO_PACKET_ENTITIES;
}

#define RECONNECT_DELAY ((unsigned int)min(qtv_max_reconnect_delay.integer, (qtv_reconnect_delay.integer * (qtv->connection_attempts))))

void QTV_ResetReconnectDelay(sv_t *qtv)
{
	qtv->connection_attempts = 1;

	// Because we backoff by x2 each time, make sure we 
	// start backing off by the value the user specified by dividing it by 2 :p
	qtv->connection_delay = max(2, qtv_reconnect_delay.integer / 2);
}

unsigned int QTV_GetReconnectDelay(sv_t *qtv)
{
	unsigned int delay = qtv_reconnect_delay.integer;

	switch (qtv_backoff.integer)
	{
		default:
		case 1:
			delay = (unsigned int)(qtv->connection_delay * 2);
			break;
		case 2:
			delay = (unsigned int)(qtv_reconnect_delay.integer * qtv->connection_attempts);
			break;
	}

	return (unsigned int)min(qtv_max_reconnect_delay.integer, delay);
}

void QTV_SetNextConnectionAttempt(sv_t *qtv)
{
	if (qtv_backoff.integer)
	{
		// Back off when trying to reconnect to a QTV source.
		qtv->NextConnectAttempt = Sys_Milliseconds() + (QTV_GetReconnectDelay(qtv) * 1000);
	}
	else
	{
		// Wait before trying to reconnect, 30 seconds default.
		qtv->NextConnectAttempt = Sys_Milliseconds() + (qtv_reconnect_delay.integer * 1000);
	}
}

qbool QTV_Connect(sv_t *qtv, const char *serverurl)
{
	char *at;
	char *ip = NULL;
	ullong now;
	size_t offset = ((size_t)&(((sv_t *)0)->mem_set_point));

	close_source(qtv, "QTV_Connect");

	// We want to save some stuff between connections, so only memset
	// a part of the sv_t struct.
	memset(((unsigned char*)qtv + offset), 0, sizeof(*qtv) - offset);

	// Set some state information that was cleared.
	now						= Sys_Milliseconds();
	qtv->curtime			= now;
	qtv->io_time			= now;
	qtv->qstate				= qs_parsingQTVheader;

	strlcpy(qtv->server, serverurl, sizeof(qtv->server));

	QTV_SetNextConnectionAttempt(qtv);

	strlcpy(qtv->gamedir, "qw", sizeof(qtv->gamedir)); // default gamedir is qw

	init_source(qtv);

	*qtv->serverinfo = '\0';

/* fixme

	{
		char qtv_version[32];
		snprintf(qtv_version, sizeof(qtv_version), "%g", QTV_VERSION);
		Info_SetValueForStarKey(qtv->serverinfo, "*qtv", 	qtv_version,	sizeof(qtv->serverinfo));
	}

	Info_SetValueForStarKey(qtv->serverinfo, "*version",	"FTEQTV",	sizeof(qtv->serverinfo));
	Info_SetValueForStarKey(qtv->serverinfo, "hostname",	qtv->cluster->hostname,	sizeof(qtv->serverinfo));
	Info_SetValueForStarKey(qtv->serverinfo, "maxclients",	"99",	sizeof(qtv->serverinfo));
	if (!strncmp(qtv->server, "file:", 5))
		Info_SetValueForStarKey(qtv->serverinfo, "server",		"file",	sizeof(qtv->serverinfo));
	else
		Info_SetValueForStarKey(qtv->serverinfo, "server",		qtv->server,	sizeof(qtv->serverinfo));
*/

	ip = qtv->server;

	if (!strncmp(ip, "tcp:", 4))
	{
		qtv->src.type = SRC_TCP;
		ip += 4;
	}
	else if (!strncmp(ip, "demo:", 5))
	{
		qtv->src.type = SRC_DEMO;
		ip += 5;
	}
	else if (!strncmp(ip, "file:", 5))
	{
		qtv->src.type = SRC_DEMO;
		ip += 5;
	}
	else
	{
		qtv->src.type = SRC_BAD;
	}

	at = strchrrev(ip, '@');
	if (at && (qtv->src.type == SRC_DEMO || qtv->src.type == SRC_TCP))
	{
		if (qtv->src.type == SRC_DEMO)
			qtv->src.type = SRC_TCP; // Seems we quering demo from other proxy, so use TCP type.
		ip = at+1;
	}

	switch(qtv->src.type)
	{
		case SRC_DEMO:
		{
			if (OpenDemoFile(qtv, ip)) 
			{  
				// Seems like success.
				Sys_Printf("%s: Playing from file %s\n", qtv->server, ip);
				QTV_SetupFrames(qtv); // This memset to 0 too some data and something also.
				qtv->parsetime = Sys_Milliseconds();
				return true;
			}

			Sys_Printf("%s: Unable to open file %s\n", qtv->server, ip);
			close_source(qtv, "QTV_Connect");
			return false;
		}
		case SRC_TCP:
		{
			if (Net_ConnectToTCPServer(qtv, ip)) 
			{
				QTV_SetupFrames(qtv); // This memset to 0 too some data and something also.
				qtv->parsetime = Sys_Milliseconds() + BUFFERTIME * 1000; // some delay before parse
				return true;
			}

			Sys_Printf("%s: Unable to connect to %s\n", qtv->server, ip);
			close_source(qtv, "QTV_Connect");
			return false;
		}
		default:
		{
			Sys_Printf("%s: Unknown source type %s\n", qtv->server, ip);

			qtv->src.type = SRC_BAD; // So no warnings in close_source().
			close_source(qtv, "QTV_Connect");
			qtv->drop = true; // Something seriously wrong, drop it.
			return false;
		}
	}
}

void QTV_Shutdown(cluster_t *cluster, sv_t *qtv)
{
	oproxy_t *next;

	qbool found = false;

   	Sys_Printf("%s: Closing source.\n", qtv->server);

	close_source(qtv, "QTV_Shutdown");

    // Unlink qtv from qtv list in cluster.
	if (cluster->servers == qtv)
	{
		 // In head
		cluster->servers = qtv->next;
		found = true;
	}
	else
	{
		sv_t *peer;

		for (peer = cluster->servers; peer && peer->next; peer = peer->next)
		{
			// In midle/end of list.
			if (peer->next == qtv) 
			{
				peer->next = qtv->next;
				found = true;
				break;
			}
		}
	}

	if (!found)
		Sys_Printf("%s: Error: QTV_Shutdown: qtv was't found in list\n", qtv->server);

	// Free proxys/clients linked to this source.

	while (qtv->proxies)
	{
		next = qtv->proxies->next;
		SV_FreeProxy(qtv->proxies);
		qtv->proxies = next;
	}

	cluster->NumServers--; // Less server connections.

	Sys_free(qtv);
}

sv_t *QTV_Stream_by_ID(unsigned int id)
{
	sv_t *qtv;

	for (qtv = g_cluster.servers; qtv; qtv = qtv->next)
	{
		if (qtv->streamid == id)
			return qtv;
	}

	return NULL;
}

static unsigned int QTV_GenerateStreamID(void)
{
	unsigned int id;

	for (id = 1; ; id++)
	{
		if (!QTV_Stream_by_ID(id))
			return id;
	}
}

sv_t *QTV_NewServerConnection(cluster_t *cluster, const char *server, char *password, qbool force, qbool autoclose, qbool noduplicates, qbool query)
{
	sv_t *qtv;

	if (noduplicates)
	{
		// Make suer we don't try to connect to an already connected server.
		for (qtv = cluster->servers; qtv; qtv = qtv->next)
		{
			if (!strcmp(qtv->server, server))
				return qtv; // We alredy have connection to this server.
		}
	}

	// FIXME:
	//	if (autoclose)
	//		if (cluster->nouserconnects)
	//			return NULL;

	if (cluster->NumServers >= maxservers.integer)
		return NULL; // Too many sources opened.

	qtv = Sys_malloc(sizeof(sv_t));

	// Setup a default config.
	strlcpy(qtv->server, PROX_DEFAULTSERVER, sizeof(qtv->server));
	strlcpy(qtv->ConnectPassword, password, sizeof(qtv->ConnectPassword));

	init_source(qtv); // Set source to proper state, SRC_BAD, thought direct call to init_source() need only here.

	qtv->DisconnectWhenNooneIsWatching = autoclose;
	qtv->EchoInServerConsole = false;

	qtv->ServerQuery = query;

	qtv->streamid = QTV_GenerateStreamID(); // assign stream ID

	// Connect to and link QTV to the cluster.
	{
		sv_t *last;

		QTV_ResetReconnectDelay(qtv);

		// Try connecting to the new QTV.
		if (!QTV_Connect(qtv, server) && !force)
		{
			Sys_free(qtv);
			return NULL;
		}

		// Link to the end of the list so that the QTVs are shown in chronological
		// order as they were added on the webpage :)
		for (last = cluster->servers; last && last->next; last = last->next)
		{
			// Find the last QTV.
		}

		// Link the new server.
		if (last)
		{
			last->next = qtv;
		}
		else
		{
			cluster->servers = qtv; // First server to be linked.
		}
	}

	cluster->NumServers++; // One more server connections.

	return qtv;
}

// add read/write stats for prox, qtv, cluster
void QTV_SocketIOStats(sv_t *qtv, int r, int w)
{
	r = max(0, r);
	w = max(0, w);

	if (r)
	{
		qtv->socket_stat.r += r; // individual
		g_cluster.socket_stat.r += r; // cummulative for all
	}

	if (w)
	{
		qtv->socket_stat.w += w; // individual
		g_cluster.socket_stat.w += w; // cummulative for all
	}
}

void Net_QueueUpstream(sv_t *qtv, int size, char *buffer)
{
	if (qtv->UpstreamBufferSize < 0 || qtv->UpstreamBufferSize > sizeof(qtv->UpstreamBuffer))
		Sys_Error("%s: Wrongly sized upstream buffer %d", qtv->server, qtv->UpstreamBufferSize); // something seriously wrong

	if (qtv->UpstreamBufferSize + size > sizeof(qtv->UpstreamBuffer))
	{
		Sys_Printf("%s: Upstream queue overflowed.\n", qtv->server);
		qtv->drop = true;
		return;
	}
	memcpy(qtv->UpstreamBuffer + qtv->UpstreamBufferSize, buffer, size);
	qtv->UpstreamBufferSize += size;
}

void Net_UpstreamPrintf(sv_t *qtv, char *fmt, ...)
{
	va_list		argptr;
	// We need somehow detect truncation, but vsnprintf() different on *nix and windows,
	// this + 10 must guarantee truncation detection by Net_QueueUpstream().
	char		string[MAX_PROXY_UPSTREAM + 10] = {0};
	
	va_start(argptr, fmt);
	vsnprintf(string, sizeof(string), fmt, argptr);
	va_end(argptr);

	Net_QueueUpstream(qtv, strlen(string), string);
}

qbool Net_WriteUpStream(sv_t *qtv)
{
	int len;

	if (qtv->UpstreamBufferSize < 0 || qtv->UpstreamBufferSize > sizeof(qtv->UpstreamBuffer))
		Sys_Error("%s: Net_WriteUpStream: Wrongly sized upstream buffer %d", qtv->server, qtv->UpstreamBufferSize); // Something seriously wrong.

	if (qtv->UpstreamBufferSize && qtv->src.type == SRC_TCP)
	{
	    if (qtv->src.s == INVALID_SOCKET)
		{
			Sys_Printf("%s: BUG: Upstream write in invalid socket\n", qtv->server);
			qtv->drop = true; // Critcal, drop it. Hrm, may be just close source so this reconnect it?
			return false;
	    }

		len = send(qtv->src.s, (char *) qtv->UpstreamBuffer, qtv->UpstreamBufferSize, 0);
		QTV_SocketIOStats(qtv, 0, len);

		if (len == 0)
			return false; // Hm, nothing was sent.

		if (len < 0)
		{
			int err = qerrno;

			if (err != EWOULDBLOCK && err != EAGAIN && err != ENOTCONN)
			{
				if (err)
					Sys_Printf("%s: Error: source socket error %i\n", qtv->server, err);
				else
					Sys_Printf("%s: Error: server disconnected\n", qtv->server);

				qtv->drop = true; // Critical, drop it, REALLY???
			}

			return false; // Nothing was sent.
		}

		qtv->UpstreamBufferSize -= len;
		memmove(qtv->UpstreamBuffer, qtv->UpstreamBuffer + len, qtv->UpstreamBufferSize);

		qtv->io_time = qtv->curtime; // Update IO activity.
	}

	return true; // Something was sent, or does't require sending.
}

qbool Net_ReadStream(sv_t *qtv)
{
	int maxreadable;
	int read = 0;
	char *buffer;
	int err;

	if ((qtv->buffersize < 0) || (qtv->buffersize > sizeof(qtv->buffer)))
		Sys_Error("%s: Net_ReadStream: Wrongly sized downstream buffer %d", qtv->server, qtv->buffersize);

	// For demos we use smaller buffer size.
	maxreadable = ((qtv->src.type == SRC_DEMO) ? PREFERED_PROXY_BUFFER : MAX_PROXY_BUFFER) - qtv->buffersize;
	if (maxreadable <= 0)
		return true; // Full buffer.

	buffer = (char *)(qtv->buffer + qtv->buffersize);

	switch (qtv->src.type)
	{
		case SRC_DEMO:
		{
			if (!qtv->src.f)
			{
				read = 0; // Will close_source().
				Sys_Printf("%s: BUG: Upstream read from wrong FILE\n", qtv->server);
				break;
			}

			read = fread(buffer, 1, maxreadable, qtv->src.f);
			break;
		}
		case SRC_TCP:
		{
			socklen_t optlen;

			if (qtv->src.s == INVALID_SOCKET)
			{
				read = 0; // Will close_source().
				Sys_Printf("%s: BUG: Upstream read from invalid socket\n", qtv->server);
				break;
			}

			// Get any socket error.
			optlen = sizeof(err);
			err = 0;
			getsockopt(qtv->src.s, SOL_SOCKET, SO_ERROR, (char *)&err, &optlen);

			if (err == ECONNREFUSED)
			{
				Sys_Printf("%s: Socket error: Server refused connection. %u attempts. Next reconnect in %u seconds...\n", qtv->server, qtv->connection_attempts, QTV_GetReconnectDelay(qtv));
				close_source(qtv, "Net_ReadStream");
				qtv->buffersize = qtv->UpstreamBufferSize = 0; // Probably contains initial connection request info.
				qtv->connection_attempts++;
				qtv->connection_delay = QTV_GetReconnectDelay(qtv);
				return false;
			}

			read = recv(qtv->src.s, buffer, maxreadable, 0);
			QTV_SocketIOStats(qtv, read, 0);
			break;
		}
		default:
		{
			return true; // Unknown or SRC_BAD type, ignoring.
		}
	}

	// Did we read something?
	if (read > 0)
	{
		qtv->io_time = qtv->curtime; // Update IO activity.

		qtv->buffersize += read;
	}
	else
	{
		// Did we just read nothing, or was there an error?
		err = (read ? qerrno : 0);

		// ENOTCONN can be returned whilst waiting for a connect to finish.
		if ((read == 0) || ((err != EWOULDBLOCK) && (err != EAGAIN) && (err != ENOTCONN)))	
		{
		    switch (qtv->src.type)
		    {
				case SRC_DEMO:
				{
					Sys_Printf("%s: Error: End of file\n", qtv->server);
					break;
				}
				case SRC_TCP:
				{
					if (read)
						Sys_Printf("%s: Error: source socket error %i.\n", qtv->server, qerrno);
					else
						Sys_Printf("%s: Error: server disconnected.\n", qtv->server);
					break;
				}
				default:
				{
					break;
				}
		    }

			close_source(qtv, "Net_ReadStream");

			return false;
		}
	}

	return true;
}

qbool QTV_ParseHeader(sv_t *qtv)
{
	float svversion;
	int length;
	char *qtvbuf = (char *)qtv->buffer;
	char *start;
	char *nl;
	char *colon;
	char *end;
	char value[128];
	char challenge[128];
	char authmethod[128];

	if (qtv->qstate != qs_parsingQTVheader)
		return false;

	*authmethod = 0;

	qtv->parsetime = qtv->curtime;

	length = min(6, qtv->buffersize);

	if (length < 6)
		return false; // Not ready yet.

	if (strncmp(qtvbuf, "QTVSV ", length))
	{
		Sys_Printf("%s: Server is not a QTV server (or is incompatible)\n", qtv->server);
		qtv->drop = true;
		return false;
	}

	QTV_ResetReconnectDelay(qtv);

	// Check for 2 new lines since that indicates the end of a request.
	{
		end = qtvbuf + qtv->buffersize - 1;
		for (nl = qtvbuf; nl < end; nl++)
		{
			if (nl[0] == '\n' && nl[1] == '\n')
				break;
		}

		if (nl == end)
			return false; // We need more header still.
	}

	// We now have a complete request!

	svversion = atof(qtvbuf + 6);

	// Server sent float version, but we compare only major version number here.
	if ((int)svversion != (int)QTV_VERSION)
	{
		Sys_Printf("%s: QTV server doesn't support a compatible protocol version, returned %.2f, need %.2f\n", qtv->server, svversion, QTV_VERSION);
		qtv->drop = true;
		return false;
	}

	// Remember version.
	qtv->svversion = svversion; 

	// Save the length of the request.
	length = (nl - qtvbuf) + 2;

	// Get rid of the second of the two ending newlines.
	end = nl;
	nl[1] = '\0';

	// Skip the first header row "QTV 1.0" so we get the actual request part.
	start = strchr(qtvbuf, '\n') + 1;

	// Go through all lines in the request.
	while ((nl = strchr(start, '\n')))
	{
		*nl = '\0';

		// A colon indicates we have a value or the request type.
		colon = strchr(start, ':');
		if (colon)
		{
			*colon = '\0';
			colon++;
			while (*colon == ' ')
				colon++;
			COM_ParseToken(colon, value, sizeof(value), NULL);
		}
		else
		{
			colon = "";
			*value = '\0';
		}

		Sys_DPrintf("%s: qtv sv, got (%s) (%s)\n", qtv->server, start, value);

		// Check the request type so we know what to expect.
		if (!strcmp(start, "AUTH"))
		{
			// The value should contain the auth method.
			strlcpy(authmethod, value, sizeof(authmethod));
		}
		else if (!strcmp(start, "CHALLENGE"))
		{
			strlcpy(challenge, colon, sizeof(challenge)); // FIXME: Why is colon used here and not value?
		}
		else if (!strcmp(start, "COMPRESSION"))
		{	
			// We don't support compression, we didn't ask for it.
			Sys_Printf("%s: QTV server wrongly used compression\n", qtv->server);

			qtv->drop = true;
			qtv->buffersize = qtv->UpstreamBufferSize = 0;

			return false;
		}
		else if (!strcmp(start, "PERROR"))
		{
			// Permanent error.
			Sys_Printf("%s:\nQTV server error: %s\n\n", qtv->server, colon); 

			qtv->drop = true;
			qtv->buffersize = qtv->UpstreamBufferSize = 0;

			return false;
		}
		else if (!strcmp(start, "TERROR") || !strcmp(start, "ERROR"))
		{ 
			// Temp error.
			Sys_Printf("%s:\nQTV server error: %s\n\n", qtv->server, colon); 

			qtv->buffersize = qtv->UpstreamBufferSize = 0;

			if (qtv->DisconnectWhenNooneIsWatching)
			{
				qtv->drop = true;	// If its a user registered stream, drop it immediatly.
			}
			else 
			{
				// Otherwise close the socket (this will result in a timeout and reconnect).
				close_source(qtv, "QTV_ParseHeader");
			}

			return false;
		}
		else if (!strcmp(start, "ASOURCE"))
		{
			Sys_Printf("%s: SRC: %s\n", qtv->server, colon);
		}
		else if (!strcmp(start, "ADEMO"))
		{
			int size;
			size = atoi(colon);
			colon = strchr(colon, ':'); // FIXME: This makes no sense, if we just did atoi(colon) then we'd expect colon to only contain a number, so why are we searching for a ":" ??
			
			colon = !colon ? "" : colon + 1;

			while (*colon == ' ')
				colon++;

			if (size > (1024 * 1024))
			{
				Sys_Printf("%s: DEMO: (%3imb) %s\n", qtv->server, size / (1024 * 1024), colon);
			}
			else
			{
				Sys_Printf("%s: DEMO: (%3ikb) %s\n", qtv->server, size / 1024, colon);
			}
		}
		else if (!strcmp(start, "PRINT"))
		{
			Sys_Printf("%s: QTV server: %s\n", qtv->server, colon);
		}
		else if (!strcmp(start, "BEGIN"))
		{
			qtv->qstate = qs_parsingconnection;
		}
		else
		{
			Sys_Printf("%s: DBG: QTV server responded with a %s key\n", qtv->server, start);
		}

		start = nl + 1;
	}

	// Get rid of the request we just read from the buffer.
	qtv->buffersize -= length;
	memmove(qtv->buffer, qtv->buffer + length, qtv->buffersize);

	if (qtv->ServerQuery)
	{
		Sys_Printf("%s: End of list\n", qtv->server);

		qtv->drop = true;
		qtv->buffersize = qtv->UpstreamBufferSize = 0;

		return false;
	}
	else if (*authmethod)
	{	
		// We need to send a challenge response now.
		Net_SendQTVConnectionRequest(qtv, authmethod, challenge);
		return false;
	}
	else if (qtv->qstate != qs_parsingconnection)
	{
		Sys_Printf("%s: QTV server sent no begin command - assuming incompatible\n\n", qtv->server);

		qtv->drop = true;
		qtv->buffersize = qtv->UpstreamBufferSize = 0;

		return false;
	}

	qtv->parsetime = Sys_Milliseconds() + BUFFERTIME * 1000;
	Sys_Printf("%s: Connection established, buffering for %i seconds\n", qtv->server, BUFFERTIME);

	Prox_UpstreamSendInitialUserList(qtv); // its time to send our userlist(if any) to upstream

	return true;
}

qbool IsSourceStream(sv_t *qtv)
{
	return (qtv->src.type == SRC_TCP || qtv->src.type == SRC_DEMO);
}

// return non zero if we have at least one message
// ms - will contain miliseconds.
int ConsistantMVDDataEx(unsigned char *buffer, int remaining, int *ms)
{
	qbool warn = true;
	int lengthofs;
	int length;
	int available = 0;

	if (ms)
		ms[0] = 0;

	while (true)
	{
		if (remaining < 2)
		{
			return available;
		}

		switch (buffer[1] & dem_mask)
		{
			case dem_set:
				length = 10;
				goto gottotallength;
			case dem_multiple:
				lengthofs = 6;
				break;
			default:
				lengthofs = 2;
				break;
		}

		if (lengthofs + 4 > remaining)
		{
			return available;
		}

		length = LittleLong(*((int *)&buffer[lengthofs]));

		if ((length > MAX_MVD_SIZE) && warn)
		{
			Sys_DPrintf("Corrupt mvd, length: %d\n", length);
			warn = false;
		}

		length += lengthofs + 4;

gottotallength:
		if (remaining < length)
		{
			return available;
		}

		// buffer[0] is the time since the last MVD message in miliseconds.
		if (ms)
			ms[0] += buffer[0];
			
		remaining -= length;
		available += length;
		buffer    += length;
	}
}

int ConsistantMVDData(unsigned char *buffer, int remaining)
{
	return ConsistantMVDDataEx(buffer, remaining, NULL);
}

int ServerInGameState(sv_t *qtv)
{
	char status[256] = {0};

	Info_ValueForKey(qtv->serverinfo, "status", status, sizeof(status));

	#if 1
	if (!stricmp(status, "Standby"))
		return 0; // game not yet started
	#else
	if (!stricmp(status, "Standby") || !stricmp(status, "Countdown"))
		return 0; // game not yet started, even we probably in Coutdown mode
	#endif

	return 1;
}

float GuessPlaybackSpeed(sv_t *qtv)
{
	int ms = 0;
	float	demospeed, desired, current;

	if (qtv->qstate != qs_active)
		return 1; // We are not ready, so use 100%.

	// This is SRC_DEMO or something, so use 100%, because buffer adjustment works badly in demo case.
	// Auto adjustment works badly because we always have too much or too less data in buffer in demo(mvd file) case.
	if (qtv->src.type != SRC_TCP)
		return 1;

	ConsistantMVDDataEx(qtv->buffer, qtv->buffersize, &ms);

	// Guess playback speed.
	if (parse_delay.value)
	{
		desired = (ServerInGameState(qtv) ? parse_delay.value : 0.5); // In prewar use short delay.
		desired = bound(0.5, desired, 20.0); // Bound it to reasonable values.
		current = 0.001 * ms;

		// qqshka: this is linear version
		demospeed = current / desired;
    
		if (demospeed >= 0.85 && demospeed <= 1.15)
			demospeed = 1.0;
    
		// Bound demospeed.
		demospeed = bound(0.1, demospeed, 3.0); // Limit demospeed at reasonable ranges.
	}
	else
	{
		demospeed = 1;
	}

	#if 0
	if (developer.integer)
	{
		static int delayer = 0; // so it does't printed each frame

		if (!((delayer++) % 500))
		{
			Sys_Printf("qtv: id: %4d, ms:%6d, speed %.3f\n", qtv->streamid, ms, demospeed);
		}
	}
	#endif

	return demospeed;
}

// We will read out as many packets as we can until we're up to date
// note: this can cause real issues when we're overloaded for any length of time
// each new packet comes with a leading msec byte (msecs from last packet)
// then a type, an optional destination mask, and a 4byte size.
// the 4 byte size is probably excessive, a short would do.
// some of the types have their destination mask encoded inside the type byte, yielding 8 types, and 32 max players.


// If we've no got enough data to read a new packet, we print a message and wait an extra two seconds. this will add a pause, 
// connected clients will get the same pause, and we'll just try to buffer more of the game before playing.
// we'll stay 2 secs behind when the tcp stream catches up, however. This could be bad especially with long up-time.
// All timings are in msecs, which is in keeping with the mvd times, but means we might have issues after 72 or so days.
// the following if statement will reset the parse timer. It might cause the game to play too soon, the buffersize checks 
// in the rest of the function will hopefully put it back to something sensible.

int QTV_ParseMVD(sv_t *qtv)
{
	int lengthofs;
	int packettime;
	int forwards = 0;

	float demospeed;

	ullong nextpackettime;
	unsigned int length;
	unsigned char *buffer;
	unsigned char message_type;

	if (qtv->qstate <= qs_parsingQTVheader)
		return 0; // We are not ready to parse.

	demospeed = max(0.001, GuessPlaybackSpeed(qtv));

	while (qtv->curtime >= qtv->parsetime)
	{
		if (qtv->buffersize < 2)
		{	
			// Not enough stuff to play.
			if (qtv->curtime > qtv->parsetime)
			{
				qtv->parsetime = qtv->curtime + 2000;	// Add two seconds.
				if (IsSourceStream(qtv))
					Sys_Printf("%s: Not enough buffered #1\n", qtv->server);
			}
			break;
		}

		buffer = qtv->buffer;
		message_type = buffer[1] & dem_mask;

		packettime     = (float)buffer[0] / demospeed;
		nextpackettime = qtv->parsetime + packettime;

		if (nextpackettime >= qtv->curtime)
			break;

		switch (message_type)
		{
			case dem_set:
			{
				length = 10;

				if (qtv->buffersize < length)
				{	
					// Not enough stuff to play.
					qtv->parsetime = qtv->curtime + 2000;	// Add two seconds.
					if (IsSourceStream(qtv))
						Sys_Printf("%s: Not enough buffered #2\n", qtv->server);

					continue;
				}

				// We're about to destroy this data, so it had better be forwarded by now!
				if (qtv->buffersize < length)
					Sys_Error ("%s: QTV_ParseMVD: qtv->buffersize < length", qtv->server);

				forwards++;
				buffer[0] = packettime; // adjust packet time according to our demospeed.
				SV_ForwardStream(qtv, qtv->buffer, length);
				qtv->buffersize -= length;
				memmove(qtv->buffer, qtv->buffer + length, qtv->buffersize);

				qtv->parsetime = nextpackettime;

				continue;
			}
			case dem_multiple:
			{
				lengthofs = 6;
				break; // Break switch().
			}
			default:
			{
				lengthofs = 2;
				break; // Break switch().
			}
		}

		if (qtv->buffersize < lengthofs + 4)
		{	
			// The size parameter doesn't fit.
			if (IsSourceStream(qtv))
				Sys_Printf("%s: Not enough buffered #3\n", qtv->server);
			qtv->parsetime = qtv->curtime + 2000;	// Add two seconds
			break;
		}

		length = LittleLong(*((int *)&buffer[lengthofs]));

		if (length > MAX_MVD_SIZE)
		{	
			// FIXME: THIS SHOULDN'T HAPPEN!
			// Blame the upstream proxy!
			Sys_Printf("%s: Warning: corrupt input packet (%i) too big! Flushing and reconnecting!\n", qtv->server, length);

			close_source(qtv, "QTV_ParseMVD");

			qtv->buffersize = qtv->UpstreamBufferSize = 0;			
			break;
		}

		if (length + lengthofs + 4 > qtv->buffersize)
		{
			if (IsSourceStream(qtv))
				Sys_Printf("%s: Not enough buffered #4\n", qtv->server);
			qtv->parsetime = qtv->curtime + 2000;	// Add two seconds.
			break;	// Can't parse it yet.
		}

		// Read the actual message.
		{
			char *messbuf = (char *)(buffer + lengthofs + 4);

			switch (message_type)
			{
				case dem_multiple:
				{
					// Read the player mask.
					unsigned int mask = LittleLong(*((unsigned int *)&buffer[lengthofs - 4])); 
					ParseMessage(qtv, messbuf, length, message_type, mask);
					break;
				}
				case dem_single:
				case dem_stats:
				{
					int playernum = (buffer[1] >> 3);	// These are directed to a single player. 
					unsigned int mask = 1 << playernum; // Set the appropriate bit in the bit mask.
					ParseMessage(qtv, messbuf, length, message_type, mask);
					break;
				}
				case dem_read:
				case dem_all:
				{
					ParseMessage(qtv, messbuf, length, message_type, 0xffffffff);
					break;
				}
				default:
				{
					Sys_Printf("%s: Message type %i\n", qtv->server, message_type);
					break;
				}
			}
		}

		length = lengthofs + 4 + length;	// Make length be the length of the entire packet

		// We're about to destroy this data, so it had better be forwarded by now!
		if (qtv->buffersize < length)
			Sys_Error ("%s: QTV_ParseMVD: qtv->buffersize < length", qtv->server);

		forwards++;
		buffer[0] = packettime; // adjust packet time according to our demospeed.
		SV_ForwardStream(qtv, qtv->buffer, length);
		qtv->buffersize -= length;
		memmove(qtv->buffer, qtv->buffer + length, qtv->buffersize);

		qtv->parsetime = nextpackettime;

		// qqshka: This was in original qtv, cause overflow in some cases.
		if (qtv->src.type == SRC_DEMO)
			Net_ReadStream(qtv); // FIXME: remove me
	}

	// Advance reconnect time in two cases: 
	//	1) when we have src 
	//  2) when we forwarded something (actually it must be when we still have something to forward, but i'm too lazy and that not really required)
	// Well, may be that not the proper way, but should work OK.
	
	if (qtv->src.type != SRC_BAD || forwards)
	{
		QTV_SetNextConnectionAttempt(qtv);
	}

	return forwards;
}

void QTV_Run(cluster_t *cluster, sv_t *qtv)
{
	if (qtv->DisconnectWhenNooneIsWatching && !qtv->proxies)
	{
		Sys_Printf("%s: Stream became inactive\n", qtv->server);
		qtv->drop = true;
	}
	
	if (!qtv->drop && (qtv->src.type == SRC_TCP) 
		&& ((qtv->io_time + 1000 * upstream_timeout.integer) <= qtv->curtime))
	{
		Sys_Printf("%s: Stream timed out\n", qtv->server);
		close_source(qtv, "QTV_Run");
	}

	if (qtv->drop)
	{
		QTV_Shutdown(cluster, qtv);
		return;
	}

	qtv->curtime = Sys_Milliseconds();

	if (qtv->src.type == SRC_BAD)
	{
		// Try connecting.
		if (qtv->curtime >= qtv->NextConnectAttempt)
		{
			if (!QTV_Connect(qtv, qtv->server))
			{
				return;
			}
		}
	}

	if (IsSourceStream(qtv))
	{
		if (!Net_ReadStream(qtv))
		{	
			// Spike's comment:
			// If we have an error reading it, if it's valid, give up
			// what should we do here?
			// obviously, we need to keep reading the stream to keep things smooth.
		}

		Net_WriteUpStream(qtv);
	}

	if (qtv->qstate == qs_parsingQTVheader)
	{
		QTV_ParseHeader(qtv);

		if (qtv->drop)
			return;
	}

	if (!QTV_ParseMVD(qtv))
		SV_ForwardStream(qtv, (unsigned char *)"", 0); // Update IO activity of QTV clients, so we can timeout them.

	Proxy_ReadProxies(qtv); // Read/parse/execute input from clients.
}

