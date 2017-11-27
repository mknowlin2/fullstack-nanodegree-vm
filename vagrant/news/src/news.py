#!/usr/bin/env python3
#
# A log web service for the 'news' database.

from flask import Flask, render_template
from newsdb import get_top_three_articles, get_most_pop_author, \
                   get_request_error_log

app = Flask(__name__)

# HTML template for an individual comment
LOG_TMPLT = '''
    <div class=logs>{} — {} views</div>
'''

LOG_TMPLT2 = '''
    <div class=logs>{} — {}% errors</div>
'''


@app.route('/', methods=['GET'])
def main():
    """Main news log page."""

    # Retrieve data from database
    article_logs = "".join(LOG_TMPLT.format(title, views)
                           for title, views in get_top_three_articles())
    author_logs = "".join(LOG_TMPLT.format(name, views)
                          for name, views in get_most_pop_author())
    err_logs = "".join(LOG_TMPLT2.format(log_date, err_pct)
                       for log_date, err_pct in get_request_error_log())

    return render_template('index.html') \
        .format(article_logs, author_logs, err_logs)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
