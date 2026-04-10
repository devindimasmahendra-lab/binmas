#!/usr/bin/env bash
gunicorn binmas:app --worker-class gevent --worke
