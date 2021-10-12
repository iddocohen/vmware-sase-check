/*
 * VMware CWS Checker - Background Script
 *
 * Iddo Cohen, October 2021
 *
 * Copyright (C) 2021, Iddo Cohen
 * SPDX-License-Identifier: MIT License
 */

import {ext} from './vmchecker.config.js';

ext.browserAction.onClicked.addListener(function(tab) {
    ext.tabs.create({ url: ext.runtime.getURL('vmchecker.tests.html')});
});
