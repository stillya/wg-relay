#!/bin/bash
systemctl stop wg-relay 2>/dev/null || true
systemctl disable wg-relay 2>/dev/null || true
