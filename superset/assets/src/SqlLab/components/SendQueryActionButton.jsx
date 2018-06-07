import React from 'react';
import PropTypes from 'prop-types';
import Button from '../../components/Button';
import { t } from '../../locales';

const propTypes = {
  // allowAsync: PropTypes.bool.isRequired,
  dbId: PropTypes.number,
  // queryState: PropTypes.string,
  sendQuery: PropTypes.func.isRequired,
  selectedText: PropTypes.string,
  // stopQuery: PropTypes.func.isRequired,
  sql: PropTypes.string.isRequired,
};
const defaultProps = {
  allowAsync: false,
  sql: '',
};

export default function SendQueryActionButton(props) {
  const sendBtnText = props.selectedText ? t('Send Selected Query') : t('Send Query');
  const btnStyle = props.selectedText ? 'warning' : 'primary';
  // const shouldShowStopBtn = ['running', 'pending'].indexOf(props.queryState) > -1;

  const commonBtnProps = {
    bsSize: 'small',
    bsStyle: btnStyle,
    disabled: !(props.dbId),
  };

  const syncBtn = (
    <Button
      {...commonBtnProps}
      onClick={() => props.sendQuery(false)}
      key="run-btn"
      tooltip={t('Send query to Soru')}
      disabled={!props.sql.trim()}
    >
      <i className="fa fa-paper-plane" /> {sendBtnText}
    </Button>
  );

  // const asyncBtn = (
  //   <Button
  //     {...commonBtnProps}
  //     onClick={() => props.runQuery(true)}
  //     key="run-async-btn"
  //     tooltip={t('Run query asynchronously')}
  //     disabled={!props.sql.trim()}
  //   >
  //     <i className="fa fa-table" /> {runBtnText}
  //   </Button>
  // );

  // const stopBtn = (
  //   <Button
  //     {...commonBtnProps}
  //     onClick={props.stopQuery}
  //   >
  //     <i className="fa fa-stop" /> {t('Stop')}
  //   </Button>
  // );

  // let button;
  // if (shouldShowStopBtn) {
  //   button = stopBtn;
  // } else if (props.allowAsync) {
  //   button = asyncBtn;
  // } else {
  //   button = syncBtn;
  // }
  return syncBtn;
}

SendQueryActionButton.propTypes = propTypes;
SendQueryActionButton.defaultProps = defaultProps;
