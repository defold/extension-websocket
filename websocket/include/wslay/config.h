/* This configuration file is used only by CMake build system. */
#ifndef CONFIG_H
#define CONFIG_H

#if defined(_WIN32)
    #define HAVE_WINSOCK2_H
#else
    #define HAVE_ARPA_INET_H
    #define HAVE_NETINET_IN_H
#endif
/* #undef HAVE_WINSOCK2_H */
/* #undef WORDS_BIGENDIAN */

#endif /* CONFIG_H */
