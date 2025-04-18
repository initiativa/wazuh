# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ToDo
- tree alerts items length is wrong
- onetomany or manytomany for wazych alert -> ticket
- check wazuh version
- assets tab, show trash problems. Not when search::show but then sort problems ????
- #8 perhaps i need to get wazuh setup to aquire scanning time
- consider some wazuhs tab access profiles
- alerts deduplication
- settings for plugin: refreshing time, request api fetch page size,

## [0.0.6] 2025-04-07
### Added
- Wazuh Alerts
- Tree table for vulnerabilities

## [0.0.5] 2025-04-05
### Added
- Default ticket ITIL Category
- Columns improvements

## [0.0.3] 2025-04-04

### Added
- Ticket creation for vulnerable devices (Computer, NetworkEq): Wazuh tab
- Ticket urgency level based on average points of severity level items attached to
- partial API fetch for long data
- fetching only data older than latest time discovered ?
- static filters for Search::show
- wazuh tab: connection problem fix
- upsert items


## [0.0.2] 2025-03-31

### Added

- Plugin initial.
- Device Wazuh's Tabs
